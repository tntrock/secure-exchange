package preview

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if o, err := Run(e.ctx, e.dir, pdftoppmTimeout, "pdftoppm", "-r", strconv.Itoa(e.cfg.DPI), "-f", "1", "-l", strconv.Itoa(pages),
		"-png", pdf, filepath.Join(e.dir, "p")); err != nil {
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

// parsePages reads the "Pages:" line of pdfinfo output.
func parsePages(out []byte) (int, error) {
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "Pages:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n <= 0 {
				return 0, errors.New("pdfinfo: bad page count")
			}
			return n, nil
		}
	}
	return 0, errors.New("pdfinfo: no page count")
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

// toolErr describes a failed external program by its error and the tail of its
// output (diagnostics, never the document itself).
func toolErr(name string, err error, out []byte) error {
	if errors.Is(err, ErrTimeout) {
		return fmt.Errorf("%s: %w", name, err)
	}
	msg := strings.TrimSpace(string(out))
	if len(msg) > 300 {
		msg = msg[len(msg)-300:]
	}
	return fmt.Errorf("%s: %w: %s", name, err, msg)
}
