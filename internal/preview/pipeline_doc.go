package preview

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// External program limits; vars so tools tests can shorten them.
var (
	sofficeTimeout  = 180 * time.Second
	pdfinfoTimeout  = 60 * time.Second
	pdftoppmTimeout = 300 * time.Second
)

const maxPageSide = 2000

// docPipeline renders a document (Office/text via LibreOffice, or a PDF) to one PNG per page.
func docPipeline(e *jobEnv) (Result, error) {
	pdf := e.in
	if !strings.EqualFold(filepath.Ext(e.in), ".pdf") {
		out := filepath.Join(e.dir, "out")
		if err := os.Mkdir(out, 0o700); err != nil {
			return Result{}, err
		}
		if o, err := Run(e.ctx, e.dir, sofficeTimeout, "soffice", "--headless", "--norestore", "--nolockcheck",
			"-env:UserInstallation=file://"+e.dir+"/profile", "--convert-to", "pdf", "--outdir", out, e.in); err != nil {
			return Result{}, toolErr("soffice", err, o)
		}
		pdfs, _ := filepath.Glob(filepath.Join(out, "*.pdf"))
		if len(pdfs) != 1 {
			return Result{}, errors.New("soffice: no PDF produced")
		}
		pdf = pdfs[0]
	}

	o, err := Run(e.ctx, e.dir, pdfinfoTimeout, "pdfinfo", pdf)
	if err != nil {
		return Result{}, toolErr("pdfinfo", err, o)
	}
	pages, err := parsePages(o)
	if err != nil {
		return Result{}, err
	}
	if pages > e.cfg.MaxPages {
		return Result{}, fmt.Errorf("%w: %d pages", errTooLarge, pages)
	}
	// page sizes bound pdftoppm's bitmap: a hostile page box must not allocate unbounded memory
	sizes, err := Run(e.ctx, e.dir, pdfinfoTimeout, "pdfinfo", "-f", "1", "-l", strconv.Itoa(pages), pdf)
	if err != nil {
		return Result{}, toolErr("pdfinfo", err, sizes)
	}
	// -cropbox: render the box pdfinfo reports sizes for (poppler clips it to the media box)
	args := append(renderScale(sizes, e.cfg.DPI), "-cropbox", "-f", "1", "-l", strconv.Itoa(pages), "-png", pdf, filepath.Join(e.dir, "p"))
	if o, err := Run(e.ctx, e.dir, pdftoppmTimeout, "pdftoppm", args...); err != nil {
		return Result{}, toolErr("pdftoppm", err, o)
	}
	files, err := pageFiles(e.dir)
	if err != nil {
		return Result{}, err
	}
	if len(files) == 0 || len(files) > pages {
		return Result{}, fmt.Errorf("pdftoppm: %d pages rendered, want %d", len(files), pages)
	}
	res := Result{Kind: KindPages, PageCount: len(files)}
	for i, f := range files {
		w, h, err := putPage(e, i, f)
		if err != nil {
			return Result{}, fmt.Errorf("page %d: %w", i+1, err)
		}
		if i == 0 {
			res.Width, res.Height = w, h
		}
		os.Remove(f) // keep tmpfs use to about one page
	}
	return res, nil
}

// putPage stores one rendered page, downscaling it when its longest side exceeds maxPageSide.
func putPage(e *jobEnv, idx int, path string) (w, h int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	img, err := decodeBounded(f)
	if err != nil {
		return 0, 0, err
	}
	b := img.Bounds()
	if max(b.Dx(), b.Dy()) > maxPageSide {
		return putPNG(e, "page", idx, fit(img, maxPageSide))
	}
	st, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}
	return b.Dx(), b.Dy(), e.put("page", idx, f, st.Size(), Item{Width: b.Dx(), Height: b.Dy()})
}

// parsePages reads the last "Pages:" line of pdfinfo output (metadata such as
// the Title, printed earlier, may contain a spoofed one).
func parsePages(out []byte) (int, error) {
	v, found := "", false
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		if rest, ok := strings.CutPrefix(s.Text(), "Pages:"); ok {
			v, found = rest, true
		}
	}
	if !found {
		return 0, errors.New("pdfinfo: no page count")
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0, errors.New("pdfinfo: bad page count")
	}
	return n, nil
}

var pageSizeRE = regexp.MustCompile(`(?m)^Page\s+\d+\s+size:\s+([0-9.]+)\s+x\s+([0-9.]+)\s+pts`)

// renderScale picks pdftoppm's resolution flags from `pdfinfo -f 1 -l N` output:
// -r DPI unless the largest page would exceed maxPageSide pixels, then -scale-to.
// Taking the max over every line means a spoofed line can only make it stricter.
func renderScale(pdfinfo []byte, dpi int) []string {
	largest := 0.0
	for _, m := range pageSizeRE.FindAllSubmatch(pdfinfo, -1) {
		for _, s := range m[1:] {
			if v, err := strconv.ParseFloat(string(s), 64); err == nil {
				largest = max(largest, v)
			}
		}
	}
	if largest <= 0 || largest/72*float64(dpi) > maxPageSide {
		return []string{"-scale-to", strconv.Itoa(maxPageSide)}
	}
	return []string{"-r", strconv.Itoa(dpi)}
}

// pageFiles lists pdftoppm's p-N.png outputs in page order (the zero padding varies with page count).
func pageFiles(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "p-*.png"))
	if err != nil {
		return nil, err
	}
	num := func(f string) int {
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "p-"), ".png"))
		return n
	}
	sort.Slice(files, func(i, j int) bool { return num(files[i]) < num(files[j]) })
	return files, nil
}

// toolErr names a failed external program by its exit status or timeout only:
// the error is stored in file_previews, and tool output can echo document text.
// The output tail goes to the debug log.
func toolErr(name string, err error, out []byte) error {
	if errors.Is(err, ErrTimeout) {
		return fmt.Errorf("%s: %w", name, err)
	}
	slog.Debug("preview: tool failed", "tool", name, "err", err, "output", string(out))
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Errorf("%s: %s", name, exit.ProcessState)
	}
	return fmt.Errorf("%s: %w", name, err)
}
