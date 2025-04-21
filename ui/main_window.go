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

type MainWindow struct {
	window fyne.Window
	db     *db.DB
	key    []byte
}

func CreateMainWindow(app fyne.App, db *db.DB, key []byte) *MainWindow {
	mw := &MainWindow{
		window: app.NewWindow("SPMS - Password Vault"),
		db:     db,
		key:    key,
	}
	mw.window.Resize(fyne.NewSize(800, 600))

	tabs := container.NewAppTabs(
		container.NewTabItem("Passwords", createPasswordTab(mw)),
		container.NewTabItem("Generator", createGeneratorTab(app)),
	)

	mw.window.SetContent(tabs)
	return mw
}

func createPasswordTab(mw *MainWindow) fyne.CanvasObject {
	list := widget.NewList(
		func() int {
			entries, err := mw.db.GetAllEntries()
			if err != nil {
				return 0
			}
			return len(entries)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.DocumentIcon()),
				widget.NewLabel("Item"),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			entries, err := mw.db.GetAllEntries()
			if err != nil {
				return
			}
			cont := obj.(*fyne.Container)
			cont.Objects[1].(*widget.Label).SetText(entries[id].Website)
		},
	)

	list.OnSelected = func(id widget.ListItemID) {
		entries, err := mw.db.GetAllEntries()
		if err != nil {
			return
		}
		showPasswordDetails(mw.window, mw.db, mw.key, entries[id], list)
	}

	addBtn := widget.NewButtonWithIcon("Add Password", theme.ContentAddIcon(), func() {
		showAddPasswordDialog(mw.window, mw.db, mw.key, func() {
			list.Refresh()
		})
	})

	changePassBtn := widget.NewButtonWithIcon("Change Master Password", theme.SettingsIcon(), func() {
		showChangePasswordDialog(mw.window, mw.db)
	})

	return container.NewBorder(
		container.NewHBox(addBtn, changePassBtn),
		nil,
		nil,
		nil,
		list,
	)
}

func showPasswordDetails(parent fyne.Window, db *db.DB, key []byte, entry db.PasswordEntry, list *widget.List) {
	var showPassword bool
	var visibilityBtn *widget.Button
	var passwordEntry *widget.Entry

	decrypted, err := crypto.Decrypt(entry.EncryptedPassword, key)
	if err != nil {
		dialog.ShowError(fmt.Errorf("decryption failed: %w", err), parent)
		return
	}
	defer crypto.ClearBytes(decrypted)

	passwordEntry = widget.NewPasswordEntry()
	passwordEntry.SetText(string(decrypted))

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

	dialog.ShowCustom(
		"Password Details",
		"Close",
		container.NewVBox(
			widget.NewLabel("Website:"),
			widget.NewLabel(entry.Website),
			widget.NewLabel("Username:"),
			widget.NewLabel(entry.Username),
			widget.NewLabel("Password:"),
			container.NewHBox(
				passwordEntry,
				visibilityBtn,
				widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
					parent.Clipboard().SetContent(string(decrypted))
				}),
			),
			widget.NewButtonWithIcon("Edit", theme.DocumentCreateIcon(), func() {
				showEditPasswordDialog(parent, db, key, entry, list)
			}),
			widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
				confirm := dialog.NewConfirm("Delete Password", "Are you sure?", func(confirmed bool) {
					if confirmed {
						if err := db.DeleteEntry(entry.ID); err != nil {
							dialog.ShowError(err, parent)
							return
						}
						list.Refresh()
					}
				}, parent)
				confirm.Show()
			}),
		),
		parent,
	)
}

func showAddPasswordDialog(parent fyne.Window, db *db.DB, key []byte, onSuccess func()) {
	var showPassword bool
	var visibilityBtn *widget.Button
	var password *widget.Entry
	var strengthLabel *widget.Label
	var categorySelect *widget.Select

	website := widget.NewEntry()
	username := widget.NewEntry()
	password = widget.NewPasswordEntry()

	categories, err := db.GetCategories()
	if err != nil {
		dialog.ShowError(err, parent)
		return
	}
	categoryOptions := []string{"None"}
	for _, cat := range categories {
		categoryOptions = append(categoryOptions, cat.Name)
	}
	categorySelect = widget.NewSelect(categoryOptions, nil)

	strengthLabel = widget.NewLabel("")
	password.OnChanged = func(text string) {
		strength := utils.EvaluatePasswordStrength(text)
		strengthLabel.SetText(fmt.Sprintf("Strength: %d%%", strength))
	}

	visibilityBtn = widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
		showPassword = !showPassword
		password.Password = !showPassword
		if showPassword {
			visibilityBtn.SetIcon(theme.VisibilityOffIcon())
		} else {
			visibilityBtn.SetIcon(theme.VisibilityIcon())
		}
		password.Refresh()
	})

	formItems := []*widget.FormItem{
		widget.NewFormItem("Website", website),
		widget.NewFormItem("Username", username),
		widget.NewFormItem("Password", container.NewHBox(password, visibilityBtn)),
		widget.NewFormItem("Category", categorySelect),
		widget.NewFormItem("", strengthLabel),
	}

	dialog.ShowForm(
		"Add New Password",
		"Add",
		"Cancel",
		formItems,
		func(confirmed bool) {
			if !confirmed {
				return
			}

			if website.Text == "" || username.Text == "" || password.Text == "" {
				dialog.ShowError(fmt.Errorf("all fields are required"), parent)
				return
			}

			var categoryID *int
			if categorySelect.Selected != "None" {
				for _, cat := range categories {
					if cat.Name == categorySelect.Selected {
						id := cat.ID
						categoryID = &id
						break
					}
				}
			}

			encrypted, err := crypto.Encrypt([]byte(password.Text), key)
			if err != nil {
				dialog.ShowError(fmt.Errorf("encryption failed: %w", err), parent)
				return
			}

			err = db.AddEntry(website.Text, username.Text, encrypted, nil, categoryID)
			if err != nil {
				dialog.ShowError(err, parent)
				return
			}
			onSuccess()
		},
		parent,
	)
}

func showEditPasswordDialog(parent fyne.Window, db *db.DB, key []byte, entry db.PasswordEntry, list *widget.List) {
	var showPassword bool
	var visibilityBtn *widget.Button
	var password *widget.Entry
	var strengthLabel *widget.Label
	var categorySelect *widget.Select

	website := widget.NewEntry()
	website.SetText(entry.Website)
	username := widget.NewEntry()
	username.SetText(entry.Username)
	password = widget.NewPasswordEntry()
	decrypted, err := crypto.Decrypt(entry.EncryptedPassword, key)
	if err != nil {
		dialog.ShowError(fmt.Errorf("decryption failed: %w", err), parent)
		return
	}
	defer crypto.ClearBytes(decrypted)
	password.SetText(string(decrypted))

	categories, err := db.GetCategories()
	if err != nil {
		dialog.ShowError(err, parent)
		return
	}
	categoryOptions := []string{"None"}
	for _, cat := range categories {
		categoryOptions = append(categoryOptions, cat.Name)
	}
	categorySelect = widget.NewSelect(categoryOptions, nil)
	if entry.CategoryID != nil {
		for _, cat := range categories {
			if cat.ID == *entry.CategoryID {
				categorySelect.SetSelected(cat.Name)
				break
			}
		}
	}

	strengthLabel = widget.NewLabel("")
	password.OnChanged = func(text string) {
		strength := utils.EvaluatePasswordStrength(text)
		strengthLabel.SetText(fmt.Sprintf("Strength: %d%%", strength))
	}

	visibilityBtn = widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
		showPassword = !showPassword
		password.Password = !showPassword
		if showPassword {
			visibilityBtn.SetIcon(theme.VisibilityOffIcon())
		} else {
			visibilityBtn.SetIcon(theme.VisibilityIcon())
		}
		password.Refresh()
	})

	formItems := []*widget.FormItem{
		widget.NewFormItem("Website", website),
		widget.NewFormItem("Username", username),
		widget.NewFormItem("Password", container.NewHBox(password, visibilityBtn)),
		widget.NewFormItem("Category", categorySelect),
		widget.NewFormItem("", strengthLabel),
	}

	dialog.ShowForm(
		"Edit Password",
		"Save",
		"Cancel",
		formItems,
		func(confirmed bool) {
			if !confirmed {
				return
			}

			if website.Text == "" || username.Text == "" || password.Text == "" {
				dialog.ShowError(fmt.Errorf("all fields are required"), parent)
				return
			}

			var categoryID *int
			if categorySelect.Selected != "None" {
				for _, cat := range categories {
					if cat.Name == categorySelect.Selected {
						id := cat.ID
						categoryID = &id
						break
					}
				}
			}

			encrypted, err := crypto.Encrypt([]byte(password.Text), key)
			if err != nil {
				dialog.ShowError(fmt.Errorf("encryption failed: %w", err), parent)
				return
			}

			err = db.UpdateEntry(entry.ID, website.Text, username.Text, encrypted, nil, categoryID)
			if err != nil {
				dialog.ShowError(err, parent)
				return
			}
			list.Refresh()
		},
		parent,
	)
}

func createGeneratorTab(app fyne.App) fyne.CanvasObject {
	length := widget.NewSlider(8, 32)
	length.SetValue(16)
	lengthLabel := widget.NewLabel(fmt.Sprintf("Length: %d", 16))

	length.OnChanged = func(v float64) {
		lengthLabel.SetText(fmt.Sprintf("Length: %d", int(v)))
	}

	includeUpper := widget.NewCheck("Uppercase", nil)
	includeLower := widget.NewCheck("Lowercase", nil)
	includeDigits := widget.NewCheck("Digits", nil)
	includeSpecial := widget.NewCheck("Special Characters", nil)

	includeUpper.SetChecked(true)
	includeLower.SetChecked(true)
	includeDigits.SetChecked(true)

	result := widget.NewEntry()
	result.Disable()

	strengthLabel := widget.NewLabel("")
	result.OnChanged = func(text string) {
		strength := utils.EvaluatePasswordStrength(text)
		strengthLabel.SetText(fmt.Sprintf("Strength: %d%%", strength))
	}

	generateBtn := widget.NewButtonWithIcon("Generate", theme.ContentAddIcon(), func() {
		config := utils.GeneratorConfig{
			Length:     int(length.Value),
			UseUpper:   includeUpper.Checked,
			UseLower:   includeLower.Checked,
			UseDigits:  includeDigits.Checked,
			UseSymbols: includeSpecial.Checked,
		}
		pass, err := utils.GeneratePassword(config)
		if err != nil {
			dialog.ShowError(err, app.NewWindow(""))
			return
		}
		result.SetText(pass)
	})

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		if result.Text != "" {
			app.Clipboard().SetContent(result.Text)
		}
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
		strengthLabel,
	)
}
