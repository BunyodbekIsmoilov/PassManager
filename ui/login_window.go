package ui

import (
	"fmt"
	"spms/crypto"
	"spms/db"

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

	_, hashedKey, err := db.GetMasterKey()
	isFirstTime := err != nil || len(hashedKey) == 0

	title := widget.NewLabel("Secure Password Manager")
	title.TextStyle = fyne.TextStyle{Bold: true, Italic: true}
	title.Alignment = fyne.TextAlignCenter

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Master Password")

	showPassword := false
	visibilityBtn := widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
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
		container.NewBorder(nil, nil, nil, visibilityBtn, passwordEntry),
		confirmEntry,
	)

	loginBtn := widget.NewButton("Login", func() {
		if isFirstTime {
			if passwordEntry.Text != confirmEntry.Text {
				dialog.ShowError(fmt.Errorf("passwords don't match"), window)
				return
			}
			if len(passwordEntry.Text) < 12 {
				dialog.ShowError(fmt.Errorf("password must be at least 12 characters"), window)
				return
			}

			salt, hashedKey, err := crypto.HashPassword(passwordEntry.Text, crypto.DefaultParams)
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if err := db.SaveMasterKey(salt, hashedKey); err != nil {
				dialog.ShowError(err, window)
				return
			}
		} else {
			salt, storedKey, err := db.GetMasterKey()
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			valid, err := crypto.VerifyPassword(passwordEntry.Text, salt, storedKey, crypto.DefaultParams)
			if err != nil || !valid {
				dialog.ShowError(fmt.Errorf("invalid master password"), window)
				return
			}
		}

		mainWindow := CreateMainWindow(app, db, passwordEntry.Text)
		window.Close()
		mainWindow.Show()
	})

	changePasswordBtn := widget.NewButton("Change Master Password", func() {
		showChangePasswordDialog(window, db)
	})
	if isFirstTime {
		changePasswordBtn.Hide()
	}

	content := container.NewVBox(
		title,
		layout.NewSpacer(),
		form,
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

	dialog.ShowCustom("Change Master Password", "Cancel",
		container.NewVBox(
			widget.NewLabel("Current Password:"),
			currentPass,
			widget.NewLabel("New Password:"),
			newPass,
			widget.NewLabel("Confirm New Password:"),
			confirmPass,
			widget.NewButton("Change", func() {
				salt, storedKey, err := db.GetMasterKey()
				if err != nil {
					dialog.ShowError(err, parent)
					return
				}

				valid, err := crypto.VerifyPassword(currentPass.Text, salt, storedKey, crypto.DefaultParams)
				if err != nil || !valid {
					dialog.ShowError(fmt.Errorf("current password is incorrect"), parent)
					return
				}

				if newPass.Text != confirmPass.Text {
					dialog.ShowError(fmt.Errorf("new passwords don't match"), parent)
					return
				}

				newSalt, newHashedKey, err := crypto.HashPassword(newPass.Text, crypto.DefaultParams)
				if err != nil {
					dialog.ShowError(err, parent)
					return
				}

				if err := db.SaveMasterKey(newSalt, newHashedKey); err != nil {
					dialog.ShowError(err, parent)
					return
				}

				dialog.ShowInformation("Success", "Master password changed", parent)
			}),
		),
		parent,
	)
}
