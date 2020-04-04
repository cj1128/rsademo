# RSADemo

A simple tool to demonstrate RSA algorithm. [RSA 的原理与实现](https://cjting.me/2020/03/13/rsa/).

First, you need to have some basic knowledge about [RSA](https://en.wikipedia.org/wiki/RSA_\(cryptosystem\)).

You need to know what `p`, `q`, `n`, `e` and `d` mean and how RSA uses them.

## Install

```bash
go get -v github.com/cj1128/rsademo
```

## Usage

```bash
$ rsademo --help
Usage of rsademo:
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
```

## Parse

Parse numbers (`n`, `e`, `d`, `p`, `q`) from public/private key file.

Supported formats are _openssh public key format_ whose content is like `ssh-rsa ....` and _openssh private key format_ whose content is like `-----BEGIN OPENSSH PRIVATE KEY----- ...`.

First, let's use `ssh-keygen` to generate a pair of RSA keys. `mkdir key && ssh-keygen -f key/rsa`.

Let's see how to get the numbers out.

```bash
$ rsademo -parse key/rsa.pub # public key
OpenSSH Public Key
  keyType: ssh-rsa
  e: 0x010001
  n: 0xCC21C75B3E1D2BF247ED4689955F8FBA1E40A865862858FBC8EC042F704BDA9D997E8F602A5841680BCCC7317A972E530F784E4DB74B732C58B1C3DB0A3A103796573608BE01DDC25A610D461C8E9BA525F55353E406D9B561A20C47E77FAF6DA8E4E9FF5340786649A8E546BE5C8DF2798AA4C822E0456CF5F37D88225F5D56F352967F51F3D3B1D573AFB8CC4D9C478009C4819A7006BD8E49CA485FE13043C303519AA669BACAA4A647E103A63D3EF8DB44D31F703133F36555D5578BC488376B20BA317E48E2F5C5391233C7E55B067C708A783CBD06401E3D2514D99678E673A21DE8F64E2E1424B359ECD5403F4957DC50A2B8EC679001D5976A6F5279
$ rsademo -parse key/rsa # private key
OpenSSH Private Key
  keyType: ssh-rsa
  n: 0xCC21C75B3E1D2BF247ED4689955F8FBA1E40A865862858FBC8EC042F704BDA9D997E8F602A5841680BCCC7317A972E530F784E4DB74B732C58B1C3DB0A3A103796573608BE01DDC25A610D461C8E9BA525F55353E406D9B561A20C47E77FAF6DA8E4E9FF5340786649A8E546BE5C8DF2798AA4C822E0456CF5F37D88225F5D56F352967F51F3D3B1D573AFB8CC4D9C478009C4819A7006BD8E49CA485FE13043C303519AA669BACAA4A647E103A63D3EF8DB44D31F703133F36555D5578BC488376B20BA317E48E2F5C5391233C7E55B067C708A783CBD06401E3D2514D99678E673A21DE8F64E2E1424B359ECD5403F4957DC50A2B8EC679001D5976A6F5279
  e: 0x010001
  d: 0x882D6098F5EEF00A49017934FF7928A0B8DDD97920EE79AE3E7374B750EAC984A9894C8C92B31DAF137020D2593DD1A18788727455FAF7727618E0D79712F50EA034BDCF47326785E855264DC76F3B5608E4881A46DC6B101D79C54792A0139FCC342A0632BBA796553D5EF6BAB773DA764A8F731411193F7F34586220CC0DAF68E1FACF6B2DEF73634B4A3A9BAE91574C7181606A55A0863547B6B07330482C8CFE4EA559D00C25A69F3D694DCAF4AE126E09DBEA9D1D7060FC14BA1123981EBE22CEC186C09EE10BC7332B252542E311FA50C88B186AA6D3BAA90777310DDD8CEA35B5D7BF5B364A39A879DBB22F3B4983B99ACFB79919E29FA234F2406881
  p: 0xFFDFAF3D203F5602EB0D593C870D08581C5AA7CAA1F4B042F8991AD869934E19C300A436ED97B06EB532A867B2B52DDAF26132D0749216E85DAD52C473BAA20E5DB821F64E7F2E5A566C4E21408E1A8EC6E6706827767FED6D81CE1252921D6AF26B91E2CB50CFBB269ADD51EA861ABBFD69EE6FB5F844068CDBC031A6DC2245
  q: 0xCC3B8F3B39EB0C5C6876A765844BFA70F8BC49B85AAD65963C3B2DAE04D24A5CD7855978A888BE0482530B0603F3E7316483BDEA305D9C4CFFD715288EF33ABA2D424ECBA1672833C5F1EA398E46888F22CADEE7BD06317BF40076BE407900F4B03414BA439B2BC8AAA5693D6EDE6C7EE391591CB07F665E220E7E34E14A0CA5
```

Useful links:

- Public key format spec [RFC4253](https://tools.ietf.org/html/rfc4253#section-6.6)
- [The SSH Public Key Format](https://coolaj86.com/articles/the-ssh-public-key-format/)
- [The OpenSSH Private Key Format](https://coolaj86.com/articles/the-openssh-private-key-format/)

## Parse with OpenSSL

We can of course use `openssl` to do the parsing.

Use `openssl` to parse the public key:

```bash
$ ssh-keygen -e -m PEM -f key/rsa.pub | openssl asn1parse -inform PEM
    0:d=0  hl=4 l= 266 cons: SEQUENCE
    4:d=1  hl=4 l= 257 prim: INTEGER           :CC21C75B3E1D2BF247ED4689955F8FBA1E40A865862858FBC8EC042F704BDA9D997E8F602A5841680BCCC7317A972E530F784E4DB74B732C58B1C3DB0A3A103796573608BE01DDC25A610D461C8E9BA525F55353E406D9B561A20C47E77FAF6DA8E4E9FF5340786649A8E546BE5C8DF2798AA4C822E0456CF5F37D88225F5D56F352967F51F3D3B1D573AFB8CC4D9C478009C4819A7006BD8E49CA485FE13043C303519AA669BACAA4A647E103A63D3EF8DB44D31F703133F36555D5578BC488376B20BA317E48E2F5C5391233C7E55B067C708A783CBD06401E3D2514D99678E673A21DE8F64E2E1424B359ECD5403F4957DC50A2B8EC679001D5976A6F5279
  265:d=1  hl=2 l=   3 prim: INTEGER           :010001
```

It's obvious that the first integer is `n` and the second integer is `e`.

Use `openssl` to parse the private key:

```bash
# first, convert openssh private key format to PEM format
# the operation is in-place, we have to copy the original file
$ cp key/rsa key/rsa.pem
$ ssh-keygen -p -m PEM -f key/rsa.pem
$ openssl asn1parse -inform PEM < key/rsa.pem
    0:d=0  hl=4 l=1189 cons: SEQUENCE
    4:d=1  hl=2 l=   1 prim: INTEGER           :00
    7:d=1  hl=4 l= 257 prim: INTEGER           :CC21C75B3E1D2BF247ED4689955F8FBA1E40A865862858FBC8EC042F704BDA9D997E8F602A5841680BCCC7317A972E530F784E4DB74B732C58B1C3DB0A3A103796573608BE01DDC25A610D461C8E9BA525F55353E406D9B561A20C47E77FAF6DA8E4E9FF5340786649A8E546BE5C8DF2798AA4C822E0456CF5F37D88225F5D56F352967F51F3D3B1D573AFB8CC4D9C478009C4819A7006BD8E49CA485FE13043C303519AA669BACAA4A647E103A63D3EF8DB44D31F703133F36555D5578BC488376B20BA317E48E2F5C5391233C7E55B067C708A783CBD06401E3D2514D99678E673A21DE8F64E2E1424B359ECD5403F4957DC50A2B8EC679001D5976A6F5279
  268:d=1  hl=2 l=   3 prim: INTEGER           :010001
  273:d=1  hl=4 l= 257 prim: INTEGER           :882D6098F5EEF00A49017934FF7928A0B8DDD97920EE79AE3E7374B750EAC984A9894C8C92B31DAF137020D2593DD1A18788727455FAF7727618E0D79712F50EA034BDCF47326785E855264DC76F3B5608E4881A46DC6B101D79C54792A0139FCC342A0632BBA796553D5EF6BAB773DA764A8F731411193F7F34586220CC0DAF68E1FACF6B2DEF73634B4A3A9BAE91574C7181606A55A0863547B6B07330482C8CFE4EA559D00C25A69F3D694DCAF4AE126E09DBEA9D1D7060FC14BA1123981EBE22CEC186C09EE10BC7332B252542E311FA50C88B186AA6D3BAA90777310DDD8CEA35B5D7BF5B364A39A879DBB22F3B4983B99ACFB79919E29FA234F2406881
  534:d=1  hl=3 l= 129 prim: INTEGER           :FFDFAF3D203F5602EB0D593C870D08581C5AA7CAA1F4B042F8991AD869934E19C300A436ED97B06EB532A867B2B52DDAF26132D0749216E85DAD52C473BAA20E5DB821F64E7F2E5A566C4E21408E1A8EC6E6706827767FED6D81CE1252921D6AF26B91E2CB50CFBB269ADD51EA861ABBFD69EE6FB5F844068CDBC031A6DC2245
  666:d=1  hl=3 l= 129 prim: INTEGER           :CC3B8F3B39EB0C5C6876A765844BFA70F8BC49B85AAD65963C3B2DAE04D24A5CD7855978A888BE0482530B0603F3E7316483BDEA305D9C4CFFD715288EF33ABA2D424ECBA1672833C5F1EA398E46888F22CADEE7BD06317BF40076BE407900F4B03414BA439B2BC8AAA5693D6EDE6C7EE391591CB07F665E220E7E34E14A0CA5
  798:d=1  hl=3 l= 129 prim: INTEGER           :D49352741709677CCF28ECDD3359E977C23EB2ADCEF589466A60508440D9E785D19303DABA734E59FB61D5B5292C0AA79EBC8FC9CD3EDD9738D45931EAEFBFD8ED959F6990F76A5C14F6AFC6426A8CB7D798F50422DCF91518E8417AC96CA8D2040AC84DC21A262AD6BCCC6854CE0B01E95C0B82758C877F65A0DFC0A05EBC7D
  930:d=1  hl=3 l= 128 prim: INTEGER           :1EF377C57605951DFC06DF5F97291C8F3A62EE992DC4D17C6F2C58C3E29F2BFDDDFBAB8F899B0F91075F267086F0D3BCBC8AEAA12F2B40A0BAB511D3CFB634D43A3FAE4955F0983B20688522ABD92CA0E498F227149277B55D4924B5B8779E19770AAD897CED6B394203476BB3FDA95BA1894983FB8B932BF8E551631A316AB1
 1061:d=1  hl=3 l= 129 prim: INTEGER           :9401971EB1B7F8BEF78177CAEF8F2AA02FFF13DEC476D8CF648980AF812CB3AD934DF3A2DD206E9E046F997B5663DB3F8248A665AE812F67A5C845A5C252E59655F68D92DB2C38D16C67449A3130225CC5E83964BF9122B86CF3274E8C8AB56E395A564A0B48DC62FE22BF28BE26C7ABECF3ECC18F31076CAAA0120D95EF3E7F
```

Here is the structure of above information. I get it from this [link](https://crypto.stackexchange.com/questions/21102/what-is-the-ssl-private-key-file-format).

```text
RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

## Generate Keypair

`rsademo` can generate all needed numbers from two prime numbers.

```bash
$ rsademo -keypair 101 103
Key details:
  p: 101
  q: 103
  n: 10403
  phi(n): 10200
  e: 7
  d: 8743
```

The algorithm is very simple. `e` is the first number from 2 ~ 65537 which is coprime to phi(n). And `d` is calculated by using [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm).

## Encrypt

We can use `rsademo` to encrypt a **number**.

Yes, a number. RSA is all about encrypting numbers.

In practice, we can intrepret any byte stream as a number in some way. But in this demo, we don't bother doing that. We just provide a number directly.

The required params are `p`, `q` and our secret number `m`.

Keys will be generated just like `rsademo -keypair p q`.

```bash
$ rsademo -enc 101 103 1024
Key details:
  p: 101
  q: 103
  n: 10403
  phi(n): 10200
  e: 7
  d: 8743
Encrypt message: 1024
Encrypt result: 9803
```

So we get it! We will tell everybody `9803`. And they can never figure our secret 1024 out 😎.

## Decrypt

Just like the encryption, but with `p`, `q` and the encrypted number.

```bash
$ rsademo -dec 101 103 9803
Key details:
  p: 101
  q: 103
  n: 10403
  phi(n): 10200
  e: 7
  d: 8743
Decrypt cipher: 9803
Decrypt result: 1024
```

Tada! 🎉 We get our secret `1024` back.

## Encrypt/Decrypt with OpenSSL

We can also use `openssl` to perform RSA encryption/decryption.

```bash
# generate our secret file
$ echo "This is our secret message." > secret.txt
# note we have to transform the public key format to PKCS8
$ openssl rsautl -encrypt -oaep -pubin -inkey <(ssh-keygen -e -m PKCS8 -f key/rsa.pub) -in secret.txt -out secret.txt.enc
# now we the encrypted file `secret.txt.enc`
# let's decrypt that file
# we need to transform the format of private key too
# here we just use key/rsa.pem mentioned previously
$ openssl rsautl -decrypt -oaep -inkey key/rsa.pem -in secret.txt.enc -out result.txt
# check whether we get our original file
$ cat result.txt
This is our secret message.
# Tada 🎉
```

NOTE: **This is just for demonstration. If you need to send a file safely, you should use [age](https://github.com/FiloSottile/age) or PGP.**

