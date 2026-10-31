package mail

import (
	"fmt"
	"time"
)

const sep = "\n\n----\n\n"

func subject(zh, en string) string { return "[secure-exchange] " + zh + " / " + en }

func Invitation(shareURL, senderName, message string, expires time.Time) (string, string) {
	zhNote, enNote := "", ""
	if message != "" {
		zhNote = "\n附言：\n" + message + "\n"
		enNote = "\nMessage:\n" + message + "\n"
	}
	ex := expires.UTC().Format("2006-01-02 15:04 UTC")
	return subject("您收到一份安全分享的檔案", "A file has been securely shared with you"),
		fmt.Sprintf("%s 與您分享了檔案。%s\n開啟連結後，請輸入寄到此信箱的驗證碼：\n%s\n\n此分享將於 %s 到期。", senderName, zhNote, shareURL, ex) +
			sep +
			fmt.Sprintf("%s has shared files with you.%s\nOpen the link and enter the verification code sent to this address:\n%s\n\nThis share expires at %s.", senderName, enNote, shareURL, ex)
}

func OTPCode(code string) (string, string) {
	return subject("您的驗證碼", "Your verification code"),
		fmt.Sprintf("您的驗證碼是：%s\n驗證碼 10 分鐘內有效，且只能使用一次。若這不是您的操作，請忽略此信。", code) +
			sep +
			fmt.Sprintf("Your verification code is: %s\nIt is valid for 10 minutes and can be used once. If you did not request it, ignore this email.", code)
}

func NotifyFirstOpen(recipient, shareURL string) (string, string) {
	return subject("收件人已開啟您的分享", "A recipient opened your share"),
		fmt.Sprintf("%s 已首次開啟您的分享：\n%s", recipient, shareURL) +
			sep +
			fmt.Sprintf("%s opened your share for the first time:\n%s", recipient, shareURL)
}

func NotifyDownload(recipient, fileName, shareURL string) (string, string) {
	return subject("收件人已下載檔案", "A recipient downloaded a file"),
		fmt.Sprintf("%s 已下載檔案「%s」：\n%s", recipient, fileName, shareURL) +
			sep +
			fmt.Sprintf("%s downloaded the file \"%s\":\n%s", recipient, fileName, shareURL)
}

func UploadInvitation(url, senderName, message string, expires time.Time) (string, string) {
	zhNote, enNote := "", ""
	if message != "" {
		zhNote = "\n附言：\n" + message + "\n"
		enNote = "\nMessage:\n" + message + "\n"
	}
	ex := expires.UTC().Format("2006-01-02 15:04 UTC")
	return subject("有人請您上傳檔案", "You have been asked to upload files"),
		fmt.Sprintf("%s 邀請您安全地上傳檔案。%s\n開啟連結後，請輸入寄到此信箱的驗證碼：\n%s\n\n此連結將於 %s 到期。", senderName, zhNote, url, ex) +
			sep +
			fmt.Sprintf("%s has asked you to upload files securely.%s\nOpen the link and enter the verification code sent to this address:\n%s\n\nThis link expires at %s.", senderName, enNote, url, ex)
}

// NotifyIntakeUpload tells the requester a file arrived; skipped means it was too large to virus-scan.
func NotifyIntakeUpload(uploader, fileName, requestURL string, skipped bool) (string, string) {
	zhNote, enNote := "", ""
	if skipped {
		zhNote = "\n注意：此檔案超過病毒掃描大小上限，未經掃描。"
		enNote = "\nNote: this file was not virus-scanned because it is over the scan size limit."
	}
	return subject("您收到一份上傳的檔案", "A file was uploaded to your request"),
		fmt.Sprintf("%s 已上傳檔案「%s」。%s\n%s", uploader, fileName, zhNote, requestURL) +
			sep +
			fmt.Sprintf("%s uploaded the file \"%s\".%s\n%s", uploader, fileName, enNote, requestURL)
}

// NotifyInfected leaves the link line out when requestURL is empty (admins cannot open the owner's request).
func NotifyInfected(uploader, fileName, signature, requestURL string) (string, string) {
	link := ""
	if requestURL != "" {
		link = "\n" + requestURL
	}
	return subject("上傳的檔案含有病毒，已隔離", "An uploaded file was infected and quarantined"),
		fmt.Sprintf("%s 上傳的檔案「%s」偵測到病毒（%s），已隔離，無法下載。%s", uploader, fileName, signature, link) +
			sep +
			fmt.Sprintf("The file \"%s\" uploaded by %s contains a virus (%s). It was quarantined and cannot be downloaded.%s", fileName, uploader, signature, link)
}

func NotifyScanError(uploader, fileName, requestURL string) (string, string) {
	return subject("上傳的檔案無法掃描", "An uploaded file could not be scanned"),
		fmt.Sprintf("%s 上傳的檔案「%s」多次掃描失敗，已封鎖，無法下載。\n%s", uploader, fileName, requestURL) +
			sep +
			fmt.Sprintf("The file \"%s\" uploaded by %s could not be virus-scanned after several attempts. It is blocked and cannot be downloaded.\n%s", fileName, uploader, requestURL)
}
