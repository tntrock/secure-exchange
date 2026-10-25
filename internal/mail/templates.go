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
