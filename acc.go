package main

import (
	"encoding/json"
	"flag"
	"fmt"
	_ "image/jpeg"
	_ "image/png"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/pschlump/ReadConfig"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/goTemplateTools"
	"github.com/pschlump/goqrcode"
	"github.com/pschlump/htotp"
)

var Cfg = flag.String("cfg", envOr("ACC_CFG", "acc.cfg.json"), "config file for this program - this is where your secret is saved. Defaults to $ACC_CFG if set.")
var DbFlag = flag.String("db_flag", "", "Additional Debug Flags")

var Import = flag.String("import", "", "Import a .png QR Code - setup for a new site or update an existing site.")
var List = flag.Bool("list", false, "Read the acc.cfg.json file and list the names of the keys")
var Get2fa = flag.String("get2fa", "", "Extract a password and 1) print it, 2) send to --output 3) copy to clipboard")
var Gen2fa = flag.String("gen2fa", "", "Fix typo")
var IsScript = flag.Bool("is_script", false, "Skip interactive - print to stdout")
var CreateUpdate = flag.String("create-update", "", "Create or update an entry in the acc.cfg.json file.  Speicify the UserName")
var Secret = flag.String("secret", "", "Secret to use with a --create-upate [UserName].")
var Password = flag.String("password", "", "Password to store with a --create-update/--enroll entry (used by --sudo-pipe).")
var GetSecret = flag.String("get-secret", "", "Retreive the secret for a user")
var CreateNewSecret = flag.Bool("create-new-secret", false, "Create a new TOTP secrent - random value")
var Issuer = flag.String("issuer", "", "Issuser/Realm to use with a --create-upate [UserName].")
var Delete = flag.String("delete", "", "Delete an entry in the acc.cfg.json file by name.")
var Verify = flag.String("verify", "", "Verify a TOTP code: --verify <name>:<code> (or --get2fa <name> --verify <code>). Exits 0 if verified, 1 if not.")
var Output = flag.String("output", "", "Output file to write TOTP value to.")
var LogFilePath = flag.String("log-file-path", "", "Use the path to access a log file that will have the URL for getting the QR in it.")
var LogFilePattern = flag.String("log-file-pattern", "", "Use the pattern to fine a URL in the log file for accessing the QR Code Image.")
var Version = flag.Bool("version", false, "print out version")
var Help = flag.Bool("help", false, "Print help message")
var Encrypted = flag.String("encrypted", "", "Password for the encrypted config. Defaults to $ACC_ENCRYPT_PW if set.")
var MinTTL = flag.Uint("min-ttl", 0, "With --get2fa/--sudo-pipe: if fewer than this many seconds remain on the code, wait for the next window and generate a fresh one.")
var ShowTTL = flag.Bool("show-ttl", false, "With --get2fa --is_script: print '<code> <seconds-left>'.")
var SudoPipe = flag.String("sudo-pipe", "", "Print '<password>\\n<totp>\\n' for the entry - pipe to 'sudo -S' (e.g. via ssh).")
var Enroll = flag.String("enroll", "", "Enroll a new user: generate a random secret, store the entry, print the provisioning URI. Requires --issuer.")
var QR = flag.String("qr", "", "With --enroll: also write a QR code .png of the provisioning URI to this file.")
var GenQR = flag.String("gen-qr", "", "Generate a scannable QR code for the named entry's provisioning URI. Prints terminal art by default; use --qr-file to write a PNG.")
var QRFile = flag.String("qr-file", "", "With --gen-qr: write the QR code as a PNG to this file (and open it if --qr-view is set).")
var QRView = flag.Bool("qr-view", false, "With --gen-qr --qr-file: open the PNG with the system viewer (Preview on macOS).")
var CheckTime = flag.String("check-time", "", "Compare the local clock with <host> (via ssh) to detect TOTP clock skew.")

// envOr returns the value of the named environment variable, or def if unset/empty.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

type ACConfigItem struct {
	Name     string `json:",omitempty"`
	Username string `json:",omitempty"`
	Password string `json:",omitempty"`
	Secret   string `json:",omitempty"`
	Realm    string `json:",omitempty"`
	LocalCfg bool   `json:"-"`
	Digits   int    `json:"Digits"`
	Notes    int    `json:"Notes,omitempty"`
}

type ACConfig struct {
	Local []ACConfigItem `json:"ac_config_item,omitempty"`
}

type GlobalConfigData struct {
	ACConfig
	Encrypted         string `json:",omitempty"`
	EncryptedData     string `json:"encrypted_data,omitempty"` // PJSenc xyzzy
	Data              string `json:",omitempty"`
	WrittenAtTimstamp string `json:",omitempty"`
	DebugFlag         string `json:"db_flag,omitempty"`
}

var gCfg GlobalConfigData
var db_flag map[string]bool

// encPassword is the resolved config-encryption password: --encrypted flag,
// or $ACC_ENCRYPT_PW if the flag is not given.
var encPassword string

func init() {
	db_flag = make(map[string]bool)
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "acc : Usage: %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `

Example: 

$ echo "Load a new QR image"
$ acc --import SomeImageQR.png

$ echo "Load a user based on name and secret"
$ acc --create-update bob3@example.com --secret "CKDPKQHM3RWX456R" --issuer example.com

$ echo "Load a user based on name and secret"
$ acc --delete Name 

$ echo "List all the configured names"
$ acc --list

$ echo "Generate a number"
$ acc --gen2fa /truckcoinswap.com:foo@example.com

$ echo "Enroll a new user (generate secret, store entry, print URI)"
$ acc --enroll phil --issuer myserver

$ echo "Print a scannable QR code for an existing entry (terminal art)"
$ acc --gen-qr myserver

$ echo "Write the QR as a PNG and open it in Preview"
$ acc --gen-qr myserver --qr-file myserver.png --qr-view

$ echo "Pipe password + TOTP code into sudo over ssh"
$ acc --sudo-pipe myserver | ssh phil@myserver 'sudo -S id'

Notes:

	Config file defaults to $ACC_CFG (or ./acc.cfg.json).
	Encryption password defaults to $ACC_ENCRYPT_PW (or --encrypted).
`)
	}

	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	if *Help {
		flag.Usage()
		os.Exit(0)
	}

	fns := flag.Args()

	if len(fns) > 0 {
		fmt.Fprintf(os.Stderr, "No additional argumetns\n")
		os.Exit(1)
	}

	// Fix my most common typo on the CLI
	if *Gen2fa != "" && *Get2fa == "" {
		*Get2fa = *Gen2fa
		x := ""
		Gen2fa = &x
	}

	if *Version {
		fmt.Printf("Version: %s\n", GitCommit)
		os.Exit(0)
	}

	// Resolve the config-encryption password: flag wins, then the environment.
	encPassword = *Encrypted
	if encPassword == "" {
		encPassword = os.Getenv("ACC_ENCRYPT_PW")
	}

	if !filelib.Exists(*Cfg) {
		fmt.Printf("Warning: creating new config file: %s\n", *Cfg)
		if encPassword != "" {
			encData, err := EncryptString([]byte("[]"), encPassword) // encrypted empty entry list
			if err != nil {
				dbgo.Fprintf(os.Stderr, "%(red)Unable to create empty encrypted data: %s\n", err)
				os.Exit(1)
			}
			err = os.WriteFile(*Cfg, []byte(fmt.Sprintf(`{"ac_config_item":[],"encrypted_data":%q,"encrypted":"y"}`, encData)), 0600)
			if err != nil {
				dbgo.Fprintf(os.Stderr, "%(red)Unable to create empty encrypted data file: %s Error:%s\n", *Cfg, err)
				os.Exit(1)
			}
		} else {
			err := os.WriteFile(*Cfg, []byte(`{"ac_config_item":[]}`), 0600)
			if err != nil {
				dbgo.Fprintf(os.Stderr, "%(red)Unable to create empty encrypted data file: %s Error:%s\n", *Cfg, err)
				os.Exit(1)
			}
		}
	}

	// ------------------------------------------------------------------------------
	// Read in Configuraiton
	// ------------------------------------------------------------------------------
	err := ReadConfig.ReadFile(*Cfg, &gCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read configuration: %s error %s\n", *Cfg, err)
		os.Exit(1)
	}

	// ------------------------------------------------------------------------------
	// If the config is encrypted, decrypt the entry list (requires the password
	// from --encrypted or $ACC_ENCRYPT_PW).
	// ------------------------------------------------------------------------------
	if gCfg.Encrypted == "y" || gCfg.EncryptedData != "" {
		if encPassword == "" {
			fmt.Fprintf(os.Stderr, "Config file %s is encrypted: supply the password via --encrypted or $ACC_ENCRYPT_PW\n", *Cfg)
			os.Exit(1)
		}
		dec, err := DecryptString(gCfg.EncryptedData, encPassword)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to decrypt configuration: %s (wrong password?)\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(dec, &gCfg.Local); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to parse decrypted configuration: %s\n", err)
			os.Exit(1)
		}
	}

	// ------------------------------------------------------------------------------
	// Debug Flag Processing
	// ------------------------------------------------------------------------------
	if gCfg.DebugFlag != "" {
		ss := strings.Split(gCfg.DebugFlag, ",")
		// fmt.Printf("gCfg.DebugFlag ->%s<-\n", gCfg.DebugFlag)
		for _, sx := range ss {
			// fmt.Printf("Setting ->%s<-\n", sx)
			db_flag[sx] = true
		}
	}
	if *DbFlag != "" {
		ss := strings.Split(*DbFlag, ",")
		// fmt.Printf("gCfg.DebugFlag ->%s<-\n", gCfg.DebugFlag)
		for _, sx := range ss {
			// fmt.Printf("Setting ->%s<-\n", sx)
			db_flag[sx] = true
		}
	}
	if db_flag["dump-db-flag"] {
		fmt.Fprintf(os.Stderr, "%sDB Flags Enabled Are:%s\n", dbgo.ColorGreen, dbgo.ColorReset)
		for x := range db_flag {
			fmt.Fprintf(os.Stderr, "%s\t%s%s\n", dbgo.ColorGreen, x, dbgo.ColorReset)
		}
	}

	// ymux.SetDbFlag(db_flag)

	// var Import = flag.String("import", "", "Import a .png QR Code - setup for a new site or update an existing site.")
	// var List = flag.Bool("list", false, "Read the ~/.ac.* file and list the names of the keys")
	// var Get2fa = flag.String("list", "", "Extract a password and 1) print it, 2) send to --output 3) copy to clipboard")

	// -----------------------------------------------------------------------------------------------------------------------
	// The intent here is to read a log-file and pull out the secret out of the log (so you don't need the .png or .svg of
	// the QR code) - and use that to setup a new HTOP set of data.
	//
	// Add in a "extract" pattern - to pull out the data.
	// -----------------------------------------------------------------------------------------------------------------------
	if *LogFilePath != "" {
		if *LogFilePattern == "" {
			fmt.Fprintf(os.Stderr, "Must supply both --log-file-path <file-name> and --log-file-pattern \"pattern\" together\n")
			os.Exit(1)
		}
		if *Import != "" {
			fmt.Fprintf(os.Stderr, "Can not spedify --import at the same time as reading a logfile for the file name\n")
			os.Exit(1)
		}
		s := ReadLogFile(*LogFilePath, *LogFilePattern)
		// xyzzy4040 - if s starts with "http" need to pull back file from server.
		Import = &s
	}

	if *Import != "" {
		uri, err := htotp.ExtractURIFromQRCodeImage(*Import)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open/process qr image. filename: %s error:%s\n", *Import, err)
			os.Exit(1)
		}

		var newCfg ACConfigItem
		uu, err := url.Parse(uri)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s at: %s\n", err, dbgo.LF())
			os.Exit(2)
		}

		if db8 {
			fmt.Printf("Scheme: ->%s<- User: ->%s<- Host: ->%s<- RawQuery: ->%s<- Fragment: ->%s<-\n", uu.Scheme, uu.User, uu.Host, uu.RawQuery, uu.Fragment)
		}

		if uu.Scheme != "otpauth" {
			fmt.Fprintf(os.Stderr, "Error: Invalid Scheme in URL, url=[%s] at: %s\n", uri, dbgo.LF())
			os.Exit(2)
		}
		newCfg.Name = uu.Path
		qq := uu.Query()
		newCfg.Realm = qq.Get("issuer")
		ss := strings.SplitN(uu.Path, ":", 2)
		if len(ss) == 2 {
			newCfg.Username = ss[1]
		} else {
			newCfg.Username = strings.TrimPrefix(uu.Path, "/")
		}
		// Normalize to uppercase: RFC 3548 base32 is case-insensitive in the
		// wild (Google Authenticator URIs often use lowercase), but the htotp
		// decoder only accepts uppercase.
		newCfg.Secret = strings.ToUpper(qq.Get("secret"))

		if pos := InConfig(gCfg.Local, newCfg.Name); pos == -1 {
			if db8 {
				fmt.Printf("Did not find\n")
			}
			gCfg.Local = append(gCfg.Local, newCfg)
			WriteConfig(gCfg)
		} else {
			if db8 {
				fmt.Printf("Found at location %d\n", pos)
			}
			gCfg.Local[pos] = newCfg
			WriteConfig(gCfg)
		}
		if *IsScript {
			fmt.Printf("%s\n", newCfg.Name)
		} else {
			fmt.Printf("Successfully imported %s\n", newCfg.Name)
		}

	} else if *CreateUpdate != "" {

		// TODO
		if *Secret == "" {
			fmt.Fprintf(os.Stderr, "Error: --secret is required with --create-update at: %s\n", dbgo.LF())
			os.Exit(2)
		}
		if *Issuer == "" {
			fmt.Fprintf(os.Stderr, "Error: --issuer is required with --create-update at: %s\n", dbgo.LF())
			os.Exit(2)
		}

		/*
			{
				"Name": "/truckcoinswap.com:bob@truckcoinswap.com",
				"Username": "bob@truckcoinswap.com",
				"Secret": "GS2RV3HVX2LTC2PZ",
				"Realm": "truckcoinswap.com",
				"Digits": 0
			}
		*/
		newCfg := ACConfigItem{
			Name:     fmt.Sprintf("/%s:%s", *Issuer, *CreateUpdate),
			Username: *CreateUpdate,
			Password: *Password,
			// Normalize to uppercase - see the --import note above.
			Secret: strings.ToUpper(*Secret),
			Realm:  *Issuer,
			Digits: 0,
		}
		if db8 {
			fmt.Printf("Config is: %s\n", dbgo.SVarI(newCfg))
		}

		if pos := InConfig(gCfg.Local, newCfg.Name); pos == -1 {
			if db8 {
				fmt.Printf("Did not find\n")
			}
			gCfg.Local = append(gCfg.Local, newCfg)
			WriteConfig(gCfg)
			if *IsScript {
				fmt.Printf("%s\n", newCfg.Name)
			} else {
				fmt.Printf("Successfully imported %s\n", newCfg.Name)
			}
		} else {
			if db8 {
				fmt.Printf("Found at location %d\n", pos)
			}
			gCfg.Local[pos] = newCfg
			WriteConfig(gCfg)
			if *IsScript {
				fmt.Printf("%s\n", newCfg.Name)
			} else {
				fmt.Printf("Successfully updated %s\n", newCfg.Name)
			}
		}

	} else if *Delete != "" {

		newCfg := ACConfigItem{
			Name: *Delete,
		}
		if db8 {
			fmt.Printf("Config To Delete Is: %s\n", dbgo.SVarI(newCfg))
		}

		if pos, err := ResolveName(gCfg.Local, newCfg.Name); err != nil {
			fmt.Printf("Did not find ->%s<- in file\n", newCfg.Name)
		} else {
			if db8 {
				fmt.Printf("Found at location %d\n", pos)
			}

			newCfg.Name = gCfg.Local[pos].Name
			gCfg.Local = goTemplateTools.RemoveFromSlice(gCfg.Local, pos)

			WriteConfig(gCfg)
			if *IsScript {
				fmt.Printf("%s\n", newCfg.Name)
			} else {
				fmt.Printf("Successfully Deleted %s\n", newCfg.Name)
			}
		}

	} else if *List {

		// fmt.Printf("%s\n", dbgo.SVarI(gCfg.Local))
		for _, ee := range gCfg.Local {
			fmt.Printf("%s\n", ee.Name)
		}

	} else if *Get2fa != "" {

		// TODO - for the moment just do "name"
		//		if # then will use that, if non number then look for it.

		var tl uint

		// Search for and get item
		if pos, err := ResolveName(gCfg.Local, *Get2fa); err == nil {
			if db8 {
				fmt.Printf("%s\n", gCfg.Local[pos].Password)
			}

			secret := gCfg.Local[pos].Secret
			un := gCfg.Local[pos].Username
			var pin string
			if *Verify != "" {
				VerifyPin(gCfg.Local, *Get2fa, *Verify)
			} else {
				pin, tl = genWithMinTTL(un, secret, uint(*MinTTL)) // generate TOTP key
				if *Output != "" {
					if err := os.WriteFile(*Output, []byte(fmt.Sprintf("%s\n", pin)), 0644); err != nil {
						fmt.Fprintf(os.Stderr, "Unable to write output to %s: %s\n", *Output, err)
						os.Exit(1)
					}
				} else {
					if *IsScript {
						if *ShowTTL {
							fmt.Printf("%s %d\n", pin, tl)
						} else {
							fmt.Printf("%s\n", pin)
						}
					} else {
						// copy to cliboard so you can paste the PIN
						if err := clipboard.WriteAll(pin); err != nil {
							fmt.Fprintf(os.Stderr, "Failed to copy to clipboard! %s\n", err)
						}
						fmt.Printf("%s2fa Key: %s%s%s for user %s%s\n", dbgo.ColorCyan, dbgo.ColorYellow, pin, dbgo.ColorCyan, un, dbgo.ColorReset)
						fmt.Printf("   ** Has been copied to clipboard **\n")
						if tl < 10 {
							fmt.Printf("\r%2d seconds left on %s%s%s    ", tl, dbgo.ColorRed, pin, dbgo.ColorReset)
						} else {
							fmt.Printf("\r%2d seconds left on %s%s%s    ", tl, dbgo.ColorYellow, pin, dbgo.ColorReset)
						}
						time.Sleep(1 * time.Second)
						for i := 2; i < int(tl); i++ {
							if (int(tl) - i) < 10 {
								fmt.Printf("\r%2d seconds left on %s%s%s    ", tl-uint(i), dbgo.ColorRed, pin, dbgo.ColorReset)
							} else {
								fmt.Printf("\r%2d seconds left on %s%s%s    ", tl-uint(i), dbgo.ColorYellow, pin, dbgo.ColorReset)
							}
							time.Sleep(1 * time.Second)
						}
						fmt.Printf("\n")
					}
				}
				if !*IsScript {
					// copy to cliboard so you can paste the PIN
					if err := clipboard.WriteAll(pin); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to copy to clipboard! %s\n", err)
					}
				}
			}

		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

	} else if *SudoPipe != "" {

		// Print "<password>\n<totp>\n" for piping into 'sudo -S'.
		if pos, err := ResolveName(gCfg.Local, *SudoPipe); err == nil {
			entry := gCfg.Local[pos]
			pin, _ := genWithMinTTL(entry.Username, entry.Secret, uint(*MinTTL))
			fmt.Printf("%s\n%s\n", entry.Password, pin)
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

	} else if *Enroll != "" {

		if *Issuer == "" {
			fmt.Fprintf(os.Stderr, "Error: --issuer is required with --enroll at: %s\n", dbgo.LF())
			os.Exit(2)
		}
		secret := htotp.RandomSecret(16)
		newCfg := ACConfigItem{
			Name:     fmt.Sprintf("/%s:%s", *Issuer, *Enroll),
			Username: *Enroll,
			Password: *Password,
			Secret:   secret,
			Realm:    *Issuer,
			Digits:   0,
		}
		if pos := InConfig(gCfg.Local, newCfg.Name); pos == -1 {
			gCfg.Local = append(gCfg.Local, newCfg)
		} else {
			gCfg.Local[pos] = newCfg
		}
		WriteConfig(gCfg)

		uri := htotp.NewDefaultTOTP(secret).ProvisioningUri(*Enroll, *Issuer)
		fmt.Printf("Name: %s\n", newCfg.Name)
		fmt.Printf("Secret: %s\n", secret)
		fmt.Printf("URI: %s\n", uri)
		fmt.Printf("\nOn the server, run 'google-authenticator' and enter this secret, or put this line\n")
		fmt.Printf("in ~%s/.google_authenticator:\n\n\t%s\n", *Enroll, secret)
		if *QR != "" {
			htotp.GenerateQRCodeFromURI(uri, *QR)
			fmt.Printf("\nQR code written to: %s\n", *QR)
		}

	} else if *CheckTime != "" {

		out, err := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", *CheckTime, "date +%s").Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to get time from %s via ssh: %s\n", *CheckTime, err)
			os.Exit(1)
		}
		remote, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to parse time from %s: %q\n", *CheckTime, strings.TrimSpace(string(out)))
			os.Exit(1)
		}
		local := time.Now().Unix()
		diff := local - remote
		abs := diff
		if abs < 0 {
			abs = -abs
		}
		fmt.Printf("Local: %d  Remote(%s): %d  Skew: %+d seconds\n", local, *CheckTime, remote, diff)
		if abs > 2 {
			fmt.Fprintf(os.Stderr, "WARNING: clock skew of %d seconds will cause TOTP failures (sync clocks with NTP)\n", abs)
			os.Exit(1)
		}

	} else if *GetSecret != "" {

		// Search for and get item
		if pos, err := ResolveName(gCfg.Local, *GetSecret); err == nil {

			secret := gCfg.Local[pos].Secret
			fmt.Printf("%s\n", secret)

		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

	} else if *CreateNewSecret {

		secret := htotp.RandomSecret(16)
		fmt.Printf("Secret: %s\n", secret)

	} else if *GenQR != "" {

		// Generate a scannable QR code for an existing entry's provisioning
		// URI.  By default the QR is printed as terminal art; --qr-file writes
		// a PNG (which scans far more reliably) and --qr-view opens it.
		if pos, err := ResolveName(gCfg.Local, *GenQR); err == nil {
			entry := gCfg.Local[pos]

			// Reconstruct the otpauth:// URI from the stored entry, matching
			// the format produced by --enroll / --create-update.
			account := entry.Username
			issuer := entry.Realm
			label := strings.TrimPrefix(entry.Name, "/")
			if issuer == "" {
				if ss := strings.SplitN(label, ":", 2); len(ss) == 2 {
					issuer = ss[0]
				} else {
					issuer = label
				}
			}
			if account == "" {
				if ss := strings.SplitN(label, ":", 2); len(ss) == 2 {
					account = ss[1]
				} else {
					account = label
				}
			}
			uri := htotp.NewDefaultTOTP(entry.Secret).ProvisioningUri(account, issuer)

			q, err := goqrcode.New(uri, goqrcode.Medium)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating QR code: %s\n", err)
				os.Exit(1)
			}

			fmt.Printf("URI: %s\n", uri)
			if *QRFile != "" {
				if err := q.WriteFile(256, *QRFile); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing QR PNG to %s: %s\n", *QRFile, err)
					os.Exit(1)
				}
				fmt.Printf("QR code written to: %s\n", *QRFile)
				if *QRView {
					if err := openFile(*QRFile); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: unable to open %s: %s\n", *QRFile, err)
					}
				}
			} else {
				// Compact terminal art; widen your terminal (or use --qr-file)
				// if it wraps or will not scan.
				fmt.Println()
				fmt.Print(q.ToSmallString(false))
			}
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

	} else if *Verify != "" {

		// Standalone verification: --verify <name>:<code>.  Entry names can
		// themselves contain a colon ("/issuer:user"), so split on the last one.
		i := strings.LastIndex(*Verify, ":")
		if i == -1 {
			fmt.Fprintf(os.Stderr, "Usage: --verify <name>:<code>   (or --get2fa <name> --verify <code>)\n")
			os.Exit(1)
		}
		VerifyPin(gCfg.Local, (*Verify)[:i], (*Verify)[i+1:])

	} else {

		fmt.Fprintf(os.Stderr, "Invalid or missing options.\n\n")
		flag.Usage()

	}
}

// VerifyPin checks a TOTP code for the named entry, prints the result, and
// exits: 0 if the code verified, 1 if it did not (or the entry was not found).
func VerifyPin(cc []ACConfigItem, name, pin string) {
	pos, err := ResolveName(cc, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	un := cc[pos].Username
	if htotp.CheckRfc6238TOTPKey(un, pin, cc[pos].Secret) {
		fmt.Printf("%sVerified: %s with user %s%s\n", dbgo.ColorGreen, pin, un, dbgo.ColorReset)
		os.Exit(0)
	}
	fmt.Printf("%sFailed To Verify: %s with user %s%s\n", dbgo.ColorRed, pin, un, dbgo.ColorReset)
	os.Exit(1)
}

func Usage(fatal bool) {
	fmt.Fprintf(os.Stderr, "Usage: acc ...\n")
	if fatal {
		os.Exit(1)
	}
}

// if pos := InConfig(gCfg.ACConfig, newCfg.Name); pos != -1 {
func InConfig(cc []ACConfigItem, name string) (pos int) {
	if len(name) > 0 && name[0:1] == "/" {
		name = name[1:]
	}
	pos = -1
	for ii, vv := range cc {

		nn := vv.Name
		if len(nn) > 0 && nn[0:1] == "/" {
			nn = nn[1:]
		}

		if nn == name {
			return ii
		}
	}
	return
}

// WriteConfig ( gCfg )
func WriteConfig(gCfg GlobalConfigData) {
	fn := *Cfg

	// TODO - backup original!
	BackupFile(fn, ".%s.bck.%%03d")

	// If an encryption password is configured (--encrypted or $ACC_ENCRYPT_PW),
	// store the entry list as an encrypted JSON blob and clear the plaintext.
	if encPassword != "" {
		if db8 {
			fmt.Fprintf(os.Stderr, "Encrypted text\n")
		}
		plaintext, err := json.Marshal(gCfg.Local)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error on marshal config: %s\n", err)
			os.Exit(1)
		}
		enctext, err := EncryptString(plaintext, encPassword)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error on encrypt config: %s\n", err)
			os.Exit(1)
		}
		gCfg.Local = []ACConfigItem{}
		gCfg.EncryptedData = enctext
		gCfg.Encrypted = "y"
	}

	if db8 {
		fmt.Fprintf(os.Stderr, "Raw ->%s<- to file %s\n", dbgo.SVarI(gCfg), fn)
	}
	//	gCfg.WrittenAtTimstamp = xxxxx
	err := os.WriteFile(fn, []byte(dbgo.SVarI(gCfg)), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error on write file: %s error: %s\n", fn, err)
		fmt.Fprintf(os.Stderr, "Failed to import!\n")
		os.Exit(1)
	}
}

// ResolveName finds an entry by exact name (with or without the leading "/"),
// falling back to a unique case-sensitive substring match. It returns an error
// when the name is not found or the substring is ambiguous.
func ResolveName(cc []ACConfigItem, name string) (pos int, err error) {
	if pos = InConfig(cc, name); pos != -1 {
		return pos, nil
	}

	query := strings.TrimPrefix(name, "/")
	if query == "" {
		return -1, fmt.Errorf("%s not found", name)
	}
	var matches []int
	for ii, vv := range cc {
		if strings.Contains(strings.TrimPrefix(vv.Name, "/"), query) {
			matches = append(matches, ii)
		}
	}
	switch len(matches) {
	case 0:
		return -1, fmt.Errorf("%s not found", name)
	case 1:
		return matches[0], nil
	default:
		names := make([]string, 0, len(matches))
		for _, ii := range matches {
			names = append(names, cc[ii].Name)
		}
		return -1, fmt.Errorf("%s is ambiguous, matches: %s", name, strings.Join(names, ", "))
	}
}

// genWithMinTTL generates a TOTP code, waiting for the next 30-second window
// if fewer than minTTL seconds remain on the current one.
func genWithMinTTL(un, secret string, minTTL uint) (pin string, tl uint) {
	for {
		pin, tl = htotp.GenerateRfc6238TOTPKeyTL(un, secret)
		if tl >= minTTL && tl > 0 {
			return
		}
		d := tl
		if d == 0 {
			d = 1
		}
		time.Sleep(time.Duration(d) * time.Second)
	}
}

func ReadLogFile(LogFilePath, LogFilePattern string) (rv string) {
	return
}

func BackupFile(fn, fn_pat string) {
	// List files - find max.
	// add 1
	// fn_pat - generate new based on max+1
	// Copy fn -> new file
}

// openFile opens a file with the platform's default GUI viewer (Preview on
// macOS, xdg-open elsewhere). Used by --gen-qr --qr-view.
func openFile(fn string) error {
	var bin string
	if runtime.GOOS == "darwin" {
		bin = "open"
	} else {
		bin = "xdg-open"
	}
	return exec.Command(bin, fn).Run()
}

const db8 = false
