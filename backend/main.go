package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/limiter"

	"envguard/backend/handlers"
)

// Embed frontend static assets into the Go binary for single-binary portability
//go:embed frontend
var embedFrontend embed.FS

func main() {
	app := fiber.New(fiber.Config{
		BodyLimit:             5 * 1024 * 1024, // Strict 5MB memory limit
		DisableStartupMessage: false,
	})

	// Rate limiter middleware (max 60 requests per minute)
	app.Use(limiter.New(limiter.Config{
		Max: 60,
	}))

	// API Routes
	api := app.Group("/api/v1")
	api.Get("/health", handlers.HandleHealth)
	api.Post("/audit", handlers.HandleAudit)
	api.Post("/sanitize", handlers.HandleSanitize)

	// Sub-filesystem for embedded frontend assets
	frontendFS, err := fs.Sub(embedFrontend, "frontend")
	if err != nil {
		log.Fatalf("Failed to load embedded frontend assets: %v", err)
	}

	// Serve Static Single Page Application (SPA)
	app.Use("/", filesystem.New(filesystem.Config{
		Root:         http.FS(frontendFS),
		Index:        "index.html",
		NotFoundFile: "index.html",
	}))

	log.Println("🛡️ EnvGuard Server running on http://localhost:8080 (Stateless In-Memory Mode)")
	log.Fatal(app.Listen(":8080"))
}
