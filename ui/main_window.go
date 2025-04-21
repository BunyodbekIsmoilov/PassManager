package ui

import (
	"fmt"
	"spms/crypto"
	"spms/db"
	"spms/utils"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func CreateMainWindow(app fyne.App, db *db.DB, masterPassword string) fyne.Window {
	window := app.NewWindow("SPMS - Password Vault")
	window.Resize(fyne.NewSize(800, 600))

	// Create tabs for different sections
	tabs := container.NewAppTabs(
		container.NewTabItem("Passwords", createPasswordTab(window, app, db, masterPassword)),
		container.NewTabItem("Generator", createGeneratorTab()),
	)

	window.SetContent(tabs)
	return window
}

func createPasswordTab(window fyne.Window, app fyne.App, db *db.DB, masterPassword string) fyne.CanvasObject {
	// Password list
	list := widget.NewList(
		func() int {
			entries, _ := db.GetAllEntries()
			return len(entries)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.DocumentIcon()),
				widget.NewLabel("Item"),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			entries, _ := db.GetAllEntries()
			cont := obj.(*fyne.Container)
			cont.Objects[1].(*widget.Label).SetText(string(entries[id].Website))
		},
	)

	// Selection actions
	list.OnSelected = func(id widget.ListItemID) {
		entries, _ := db.GetAllEntries()
		showPasswordDetails(window, app, db, masterPassword, entries[id])
	}

	// Add new password button
	addBtn := widget.NewButtonWithIcon("Add Password", theme.ContentAddIcon(), func() {
		showAddPasswordDialog(window, app, db, masterPassword, func() {
			list.Refresh()
		})
	})

	return container.NewBorder(
		addBtn,
		nil,
		nil,
		nil,
		list,
	)
}

func showPasswordDetails(parent fyne.Window, app fyne.App, db *db.DB, masterPassword string, entry db.PasswordEntry) {
	decrypted, _ := crypto.Decrypt(entry.EncryptedPassword, []byte(masterPassword))

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetText(string(decrypted))

	dialog.ShowCustom(
		"Password Details",
		"Close",
		container.NewVBox(
			widget.NewLabel("Website:"),
			widget.NewLabel(string(entry.Website)),
			widget.NewLabel("Username:"),
			widget.NewLabel(string(entry.Username)),
			widget.NewLabel("Password:"),
			container.NewHBox(
				passwordEntry,
				widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
					app.Clipboard().SetContent(string(decrypted))
				}),
			),
		),
		parent,
	)
}

func showAddPasswordDialog(parent fyne.Window, app fyne.App, db *db.DB, masterPassword string, onSuccess func()) {
	website := widget.NewEntry()
	username := widget.NewEntry()
	password := widget.NewEntry()

	dialog.ShowForm(
		"Add New Password",
		"Add",
		"Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Website", website),
			widget.NewFormItem("Username", username),
			widget.NewFormItem("Password", password),
		},
		func(confirmed bool) {
			if !confirmed {
				return
			}

			encrypted, _ := crypto.Encrypt([]byte(password.Text), []byte(masterPassword))
			db.AddEntry(
				[]byte(website.Text),
				[]byte(username.Text),
				encrypted,
				nil,
				nil,
			)
			onSuccess()
		},
		parent,
	)
}

func createGeneratorTab() fyne.CanvasObject {
	length := widget.NewSlider(8, 32)
	length.SetValue(16)
	lengthLabel := widget.NewLabel(fmt.Sprintf("Length: %d", 16))

	length.OnChanged = func(v float64) {
		lengthLabel.SetText(fmt.Sprintf("Length: %d", int(v)))
	}

	includeUpper := widget.NewCheck("Uppercase", nil)
	includeLower := widget.NewCheck("Lowercase", nil)
	includeDigits := widget.NewCheck("Digits", nil)
	includeSpecial := widget.NewCheck("Special", nil)

	// Set defaults
	includeUpper.SetChecked(true)
	includeLower.SetChecked(true)
	includeDigits.SetChecked(true)

	result := widget.NewEntry()
	result.Disable()

	generateBtn := widget.NewButton("Generate", func() {
		config := utils.GeneratorConfig{
			Length:     int(length.Value),
			UseUpper:   includeUpper.Checked,
			UseLower:   includeLower.Checked,
			UseDigits:  includeDigits.Checked,
			UseSymbols: includeSpecial.Checked,
		}
		pass, _ := utils.GeneratePassword(config)
		result.SetText(pass)
	})

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		// Clipboard handling would go here
	})

	return container.NewVBox(
		widget.NewLabel("Password Generator"),
		lengthLabel,
		length,
		includeUpper,
		includeLower,
		includeDigits,
		includeSpecial,
		generateBtn,
		container.NewHBox(result, copyBtn),
	)
}
