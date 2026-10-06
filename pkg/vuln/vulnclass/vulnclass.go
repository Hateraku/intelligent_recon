// Package vulnclass è la tassonomia CONDIVISA delle classi di vulnerabilità,
// trasversale alle tecnologie.
//
// Una classe descrive il MECCANISMO (deserializzazione non fidata, SSRF,
// prototype pollution…), non il prodotto. È definita qui UNA sola volta e viene
// referenziata dai Check delle varie famiglie: il check React per la
// deserializzazione RSC e un eventuale check Java per ObjectInputStream puntano
// alla STESSA classe, senza duplicarne il concetto. Ciò che cambia tra le due è
// solo il rilevamento (Detect), non la classe.
package vulnclass

// Class è una voce di tassonomia (stile CWE): il meccanismo, non l'istanza.
type Class struct {
	ID          string // slug stabile, es. "untrusted-deserialization"
	Name        string // nome leggibile
	CWE         string // riferimento CWE, es. "CWE-502"
	Description string // descrizione generica, indipendente dalla tecnologia
}

// Classi note. Sono dati condivisi: aggiungere una classe qui la rende
// disponibile a tutte le famiglie.
var (
	UntrustedDeserialization = Class{
		ID:          "untrusted-deserialization",
		Name:        "Deserializzazione non fidata",
		CWE:         "CWE-502",
		Description: "Il server deserializza dati controllati dall'attaccante, permettendo di influenzare oggetti o flusso di esecuzione (spesso fino alla RCE).",
	}

	InfoDisclosure = Class{
		ID:          "info-disclosure",
		Name:        "Divulgazione di informazioni",
		CWE:         "CWE-200",
		Description: "L'applicazione espone informazioni (framework, versioni, percorsi) che riducono il costo di ricognizione per un attaccante.",
	}

	// Seed della tassonomia per famiglie/check futuri (ancora non usati).
	PrototypePollution = Class{
		ID:          "prototype-pollution",
		Name:        "Prototype pollution",
		CWE:         "CWE-1321",
		Description: "Modifica di proprietà del prototype di oggetti (es. Object.prototype) che altera il comportamento dell'applicazione, talvolta fino alla RCE.",
	}

	AuthBypass = Class{
		ID:          "auth-bypass",
		Name:        "Bypass dell'autorizzazione",
		CWE:         "CWE-285",
		Description: "Controlli di autorizzazione aggirabili, con accesso a risorse o funzioni riservate.",
	}

	SQLInjection = Class{
		ID:          "sql-injection",
		Name:        "SQL injection",
		CWE:         "CWE-89",
		Description: "Input non sanitizzato interpolato in una query SQL, con alterazione della query o accesso ai dati.",
	}

	XSS = Class{
		ID:          "xss",
		Name:        "Cross-site scripting (XSS)",
		CWE:         "CWE-79",
		Description: "Input dell'utente riflesso/memorizzato senza codifica, eseguibile come script nel browser della vittima.",
	}

	PathTraversal = Class{
		ID:          "path-traversal",
		Name:        "Path traversal",
		CWE:         "CWE-22",
		Description: "Manipolazione di percorsi (../) per accedere a file fuori dalla directory prevista.",
	}

	CommandInjection = Class{
		ID:          "command-injection",
		Name:        "OS command injection",
		CWE:         "CWE-78",
		Description: "Input non sanitizzato passato a un comando di sistema, con esecuzione di comandi arbitrari.",
	}

	SensitiveFileExposure = Class{
		ID:          "sensitive-file-exposure",
		Name:        "Esposizione di file sensibili",
		CWE:         "CWE-538",
		Description: "File o directory sensibili (segreti, sorgenti, backup) raggiungibili dalla webroot.",
	}

	SecurityMisconfiguration = Class{
		ID:          "security-misconfiguration",
		Name:        "Configurazione di sicurezza errata",
		CWE:         "CWE-16",
		Description: "Componenti o interfacce amministrative/di debug esposti o configurati in modo insicuro.",
	}

	HardcodedSecret = Class{
		ID:          "hardcoded-secret",
		Name:        "Credenziali/segreti esposti",
		CWE:         "CWE-798",
		Description: "Chiavi API, token o credenziali presenti nel contenuto servito al client.",
	}
)
