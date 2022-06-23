package main

import (
	"flag"
	"fmt"
	_ "image/jpeg"
	_ "image/png"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/pschlump/ReadConfig"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	goTemplateTools "github.com/pschlump/go-template-tools"
	"github.com/pschlump/htotp"
)

// xyzzy4040 - need to pull back file from server.

var Cfg = flag.String("cfg", "acc.cfg.json", "config file for this program - this is where your secret is saved.")
var DbFlag = flag.String("db_flag", "", "Additional Debug Flags")

var Import = flag.String("import", "", "Import a .png QR Code - setup for a new site or update an existing site.")
var List = flag.Bool("list", false, "Read the acc.cfg.json file and list the names of the keys")
var Get2fa = flag.String("get2fa", "", "Extract a password and 1) print it, 2) send to --output 3) copy to clipboard")
var Gen2fa = flag.String("gen2fa", "", "Fix typo")
var IsScript = flag.Bool("is_script", false, "Skip interactive - print to stdout")
var CreateUpdate = flag.String("create-update", "", "Create or update an entry in the acc.cfg.json file.  Speicify the UserName")
var Secret = flag.String("secret", "", "Secret to use with a --create-upate [UserName].")
var Issuer = flag.String("issuer", "", "Issuser/Realm to use with a --create-upate [UserName].")
var Delete = flag.String("delete", "", "Delete an entry in the acc.cfg.json file by name.")
var Verify = flag.String("verify", "", "Verify an existing TOTP code.")
var Output = flag.String("output", "", "Output file to write TOTP value to.")
var LogFilePath = flag.String("log-file-path", "", "Use the path to access a log file that will have the URL for getting the QR in it.")
var LogFilePattern = flag.String("log-file-pattern", "", "Use the pattern to fine a URL in the log file for accessing the QR Code Image.")
var Version = flag.Bool("version", false, "print out version")
var Help = flag.Bool("help", false, "Print help message")

type ACConfigItem struct {
	Name     string `json:",omitempty"`
	Username string `json:",omitempty"`
	Password string `json:",omitempty"`
	Secret   string `json:",omitempty"`
	Realm    string `json:",omitempty"`
	LocalCfg bool   `json:"-"`
	Digits   int    `json:"Digits"`
}

type ACConfig struct {
	Local []ACConfigItem `json:"ac_config_item,omitempty"`
}

type GlobalConfigData struct {
	ACConfig
	Encrypted string `json:",omitempty"`
	Data      string `json:",omitempty"`
	DebugFlag string `json:"db_flag,omitempty"`
}

var gCfg GlobalConfigData
var db_flag map[string]bool
var logFilePtr *os.File

func init() {
	logFilePtr = os.Stderr
	db_flag = make(map[string]bool)
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "REST_Easy : Usage: %s [flags]\n", os.Args[0])
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

Path to Code:
	/Users/philip/go/src/github.com/pschlump/htotp_acc
Build Date:
	Tue May 31 20:49:50 MDT 2022
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

	if !filelib.Exists(*Cfg) {
		fmt.Printf("Warning: creating new config file: %s\n", *Cfg)
		ioutil.WriteFile(*Cfg, []byte(`{"ac_config_item":[]}`), 0600)
	}

	// ------------------------------------------------------------------------------
	// Read in Configuraiton
	// ------------------------------------------------------------------------------
	// err := ReadConfig.ReadEncryptedFile(*Cfg, *PromptPassword, *Password, &gCfg)
	err := ReadConfig.ReadFile(*Cfg, &gCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read configuration: %s error %s\n", *Cfg, err)
		os.Exit(1)
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
		if strings.HasPrefix(s, "http") {
			// xyzzy4040 - need to pull back file from server.
		}
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
		ss := strings.Split(uu.Path, ":")
		newCfg.Username = ss[1]
		newCfg.Secret = qq.Get("secret")

		if pos := InConfig(gCfg.ACConfig.Local, newCfg.Name); pos == -1 {
			if db8 {
				fmt.Printf("Did not find\n")
			}
			gCfg.ACConfig.Local = append(gCfg.ACConfig.Local, newCfg)
			WriteConfig(gCfg)
		} else {
			if db8 {
				fmt.Printf("Found at location %d\n", pos)
			}
			gCfg.ACConfig.Local[pos] = newCfg
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
			Secret:   *Secret,
			Realm:    *Issuer,
			Digits:   0,
		}
		if db8 {
			fmt.Printf("Config is: %s\n", dbgo.SVarI(newCfg))
		}

		if pos := InConfig(gCfg.ACConfig.Local, newCfg.Name); pos == -1 {
			if db8 {
				fmt.Printf("Did not find\n")
			}
			gCfg.ACConfig.Local = append(gCfg.ACConfig.Local, newCfg)
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
			gCfg.ACConfig.Local[pos] = newCfg
			WriteConfig(gCfg)
			if *IsScript {
				fmt.Printf("%s\n", newCfg.Name)
			} else {
				fmt.Printf("Successfully updated %s\n", newCfg.Name)
			}
		}

	} else if *Delete != "" {

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
			Name: fmt.Sprintf("/%s:%s", *Issuer, *CreateUpdate),
		}
		if db8 {
			fmt.Printf("Config To Delete Is: %s\n", dbgo.SVarI(newCfg))
		}

		if pos := InConfig(gCfg.ACConfig.Local, newCfg.Name); pos == -1 {
			fmt.Printf("Did not find ->%s<- in file\n", newCfg.Name)
		} else {
			if db8 {
				fmt.Printf("Found at location %d\n", pos)
			}

			gCfg.ACConfig.Local = goTemplateTools.RemoveFromSlice(gCfg.ACConfig.Local, pos)

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
		if pos := InConfig(gCfg.ACConfig.Local, *Get2fa); pos != -1 {
			if db8 {
				fmt.Printf("%s\n", gCfg.ACConfig.Local[pos].Password)
			}

			secret := gCfg.ACConfig.Local[pos].Secret
			un := gCfg.ACConfig.Local[pos].Username
			var pin string
			if *Verify != "" {
				pin = *Verify
				if htotp.CheckRfc6238TOTPKey(un, pin, secret) {
					fmt.Printf("%sVerified: %s with user %s%s\n", dbgo.ColorGreen, pin, un, dbgo.ColorReset)
				} else {
					fmt.Printf("%sFailed To Verifiy: %s with user %s%s\n", dbgo.ColorRed, pin, un, dbgo.ColorReset)
				}
			} else {
				pin, tl = htotp.GenerateRfc6238TOTPKeyTL(un, secret) // generate TOTP key
				if *Output != "" {
					ioutil.WriteFile(*Output, []byte(fmt.Sprintf("%s\n", pin)), 0644)
				} else {
					if *IsScript {
						fmt.Printf("%s\n", pin)
					} else {
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
			fmt.Fprintf(os.Stderr, "%s not found\n", *Get2fa)
			os.Exit(1)
		}

	} else {

		fmt.Fprintf(os.Stderr, "Invalid options - probably not implemented yet.\n")

	}
}

func Usage(fatal bool) {
	fmt.Fprintf(os.Stderr, "Usage: acc ...\n")
	if fatal {
		os.Exit(1)
	}
}

// if pos := InConfig(gCfg.ACConfig, newCfg.Name); pos != -1 {
func InConfig(cc []ACConfigItem, name string) (pos int) {
	if name[0:1] == "/" {
		name = name[1:]
	}
	pos = -1
	for ii, vv := range cc {

		nn := vv.Name
		if nn[0:1] == "/" {
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
	if db8 {
		fmt.Fprintf(os.Stderr, "Raw ->%s<- to file %s\n", dbgo.SVarI(gCfg), fn)
	}
	err := ioutil.WriteFile(fn, []byte(dbgo.SVarI(gCfg)), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error on write file: %s error: %s\n", fn, err)
		fmt.Fprintf(os.Stderr, "Failed to import!\n")
		os.Exit(1)
	}
}

func ReadLogFile(LogFilePath, LogFilePattern string) (rv string) {
	return
}

const db8 = false
