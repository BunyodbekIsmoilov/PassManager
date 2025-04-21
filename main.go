package main

import (
	"log"
	"spms/db"
	"spms/ui"

	"fyne.io/fyne/v2/app"
)

func main() {
	myApp := app.New()

	// Initialize database
	database, err := db.NewDB("vault.db")
	if err != nil {
		log.Fatal("Database initialization failed:", err)
	}
	defer database.Close()

	// Create and show login window
	loginWindow := ui.CreateLoginWindow(myApp, database)
	loginWindow.Show()

	myApp.Run()
}
