// Package workflows incorpora i file di workflow YAML nel binario, così i
// preset predefiniti (full, quick, api) funzionano anche senza i file su disco.
// I file restano comunque in configs/workflows/ per essere letti e modificati.
package workflows

import "embed"

//go:embed *.yaml
var FS embed.FS
