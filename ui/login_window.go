package ui

import (
	"crypto/rand"
	"fmt"
	"spms/crypto"
	"spms/db"
	"spms/utils"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func CreateLoginWindow(app fyne.App, db *db.DB) fyne.Window {
	window := app.NewWindow("SPMS - Login")
	window.Resize(fyne.NewSize(500, 400))
	window.SetFixedSize(true)

	_, encryptedCheck, err := db.GetMasterKey()
	isFirstTime := err != nil || len(encryptedCheck) == 0

	title := widget.NewLabel("Secure Password Manager")
	title.TextStyle = fyne.TextStyle{Bold: true, Italic: true}
	title.Alignment = fyne.TextAlignCenter

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Master Password")

	strengthLabel := widget.NewLabel("")
	passwordEntry.OnChanged = func(text string) {
		strength := utils.EvaluatePasswordStrength(text)
		strengthLabel.SetText(fmt.Sprintf("Strength: %d%%", strength))
	}

	var visibilityBtn *widget.Button
	showPassword := false
	visibilityBtn = widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
		showPassword = !showPassword
		passwordEntry.Password = !showPassword
		if showPassword {
			visibilityBtn.SetIcon(theme.VisibilityOffIcon())
		} else {
			visibilityBtn.SetIcon(theme.VisibilityIcon())
		}
		passwordEntry.Refresh()
	})

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirm Master Password")
	if !isFirstTime {
		confirmEntry.Hide()
	}

	form := container.NewVBox(
		container.NewBorder(nil, nil, nil, nil, passwordEntry),
		confirmEntry,
		strengthLabel,
	)

	loginBtn := widget.NewButtonWithIcon("Login", theme.LoginIcon(), func() {
		if isFirstTime {
			if passwordEntry.Text != confirmEntry.Text {
				dialog.ShowError(fmt.Errorf("passwords don't match"), window)
				return
			}
			if len(passwordEntry.Text) < 12 {
				dialog.ShowError(fmt.Errorf("password must be at least 12 characters"), window)
				return
			}

			salt := make([]byte, crypto.DefaultParams.SaltLength)
			if _, err := rand.Read(salt); err != nil {
				dialog.ShowError(err, window)
				return
			}

			key, err := crypto.DeriveKey(passwordEntry.Text, salt)
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			defer crypto.ClearBytes(key)

			encryptedCheck, err := crypto.GetEncryptedCheck(key)
			if err != nil {
				dialog.ShowError(err, window)
				return
			}

			if err := db.SaveMasterKey(salt, encryptedCheck); err != nil {
				dialog.ShowError(err, window)
				return
			}

			mainWindow := CreateMainWindow(app, db, key)
			window.Close()
			mainWindow.window.Show()
		} else {
			salt, encryptedCheck, err := db.GetMasterKey()
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			key, err := crypto.DeriveKey(passwordEntry.Text, salt)
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			defer crypto.ClearBytes(key)

			if !crypto.VerifyMasterKey(key, encryptedCheck) {
				dialog.ShowError(fmt.Errorf("invalid master password"), window)
				return
			}

			mainWindow := CreateMainWindow(app, db, key)
			window.Close()
			mainWindow.window.Show()
		}
	})

	changePasswordBtn := widget.NewButtonWithIcon("Change Master Password", theme.SettingsIcon(), func() {
		showChangePasswordDialog(window, db)
	})
	if isFirstTime {
		changePasswordBtn.Hide()
	}

	content := container.NewVBox(
		title,
		layout.NewSpacer(),
		form,
		layout.NewSpacer(),
		loginBtn,
		changePasswordBtn,
		layout.NewSpacer(),
	)

	window.SetContent(content)
	return window
}

func showChangePasswordDialog(parent fyne.Window, db *db.DB) {
	currentPass := widget.NewPasswordEntry()
	newPass := widget.NewPasswordEntry()
	confirmPass := widget.NewPasswordEntry()

	strengthLabel := widget.NewLabel("")
	newPass.OnChanged = func(text string) {
		strength := utils.EvaluatePasswordStrength(text)
		strengthLabel.SetText(fmt.Sprintf("Strength: %d%%", strength))
	}

	dialog.ShowCustom("Change Master Password", "Cancel",
		container.NewVBox(
			widget.NewLabel("Current Password:"),
			currentPass,
			widget.NewLabel("New Password:"),
			newPass,
			widget.NewLabel("Confirm New Password:"),
			confirmPass,
			strengthLabel,
			widget.NewButtonWithIcon("Change", theme.ConfirmIcon(), func() {
				salt, encryptedCheck, err := db.GetMasterKey()
				if err != nil {
					dialog.ShowError(err, parent)
					return
				}

				oldKey, err := crypto.DeriveKey(currentPass.Text, salt)
				if err != nil {
					dialog.ShowError(err, parent)
					return
				}
				defer crypto.ClearBytes(oldKey)

				if !crypto.VerifyMasterKey(oldKey, encryptedCheck) {
					dialog.ShowError(fmt.Errorf("current password is incorrect"), parent)
					return
				}

				if newPass.Text != confirmPass.Text {
					dialog.ShowError(fmt.Errorf("new passwords don't match"), parent)
					return
				}

				if len(newPass.Text) < 16 {
					dialog.ShowError(fmt.Errorf("new password must be at least 16 characters"), parent)
					return
				}

				newSalt := make([]byte, crypto.DefaultParams.SaltLength)
				if _, err := rand.Read(newSalt); err != nil {
					dialog.ShowError(err, parent)
					return
				}

				newKey, err := crypto.DeriveKey(newPass.Text, newSalt)
				if err != nil {
					dialog.ShowError(err, parent)
					return
				}
				defer crypto.ClearBytes(newKey)

				newEncryptedCheck, err := crypto.GetEncryptedCheck(newKey)
				if err != nil {
					dialog.ShowError(err, parent)
					return
				}

				entries, err := db.GetAllEntries()
				if err != nil {
					dialog.ShowError(err, parent)
					return
				}

				for _, entry := range entries {
					decrypted, err := crypto.Decrypt(entry.EncryptedPassword, oldKey)
					if err != nil {
						continue // Skip failed decryptions
					}
					newEncrypted, err := crypto.Encrypt(decrypted, newKey)
					if err != nil {
						continue // Skip failed encryptions
					}
					err = db.UpdateEntry(entry.ID, entry.Website, entry.Username, newEncrypted, entry.Notes, entry.CategoryID)
					if err != nil {
						continue // Skip failed updates
					}
				}

				if err := db.SaveMasterKey(newSalt, newEncryptedCheck); err != nil {
					dialog.ShowError(err, parent)
					return
				}

				dialog.ShowInformation("Success", "Master password changed", parent)
			}),
		),
		parent,
	)
}
