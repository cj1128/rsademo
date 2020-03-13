package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func printUsage() {
	fmt.Fprint(flag.CommandLine.Output(), `Usage of rsademo:
  -parse <key_file>
      parse numbers from open ssh public/private key file
  -keypair <p> <q>
      generate key paris using p and q two prime numbers
  -enc <p> <q> <message>
      encrypt message using keypairs generated from p and q
  -dec <p> <q> <cipher>
      decrypt cipher using keypairs generated from p and q

NOTE: p, q, message and cipher are all nubmers(int64)
e.g. 
  generate keys for RSA: rsademo -keypair 3 7
  parse open ssh key file: rsademo -parse ~/.ssh/id_rsa
  encrypt a number: rsademo -enc 101 103 1024
  decrypt the encrypted number: rsademo -dec 101 103 9803
`)
}

func main() {
	encMode := flag.Bool("enc", false, "")
	decMode := flag.Bool("dec", false, "")
	parseMode := flag.Bool("parse", false, "")
	keyPairMode := flag.Bool("keypair", false, "")

	flag.Usage = printUsage
	flag.Parse()

	args := flag.Args()

	switch true {
	case *keyPairMode:
		{
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, `need two args, rsademo -keypair <p> <q>`)
				os.Exit(1)
			}

			key, err := genKeyPair(args[0], args[1])
			if err != nil {
				log.Fatalln(err)
			}

			fmt.Println(key)
		}

	case *encMode:
		{
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, `need three args, rsademo -enc <p> <q> <message>`)
				os.Exit(1)
			}

			encrypt(args[0], args[1], args[2])
		}

	case *decMode:
		{
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, `need three args, rsademo -enc <p> <q> <message>`)
				os.Exit(1)
			}

			decrypt(args[0], args[1], args[2])
		}

	case *parseMode:
		{
			if len(args) < 1 {
				fmt.Fprintln(os.Stderr, `need one arg, rsademo -parse <key_file>`)
				os.Exit(1)
			}
			parse(args[0])
		}

	default:
		printUsage()
	}
}
