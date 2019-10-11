# pki_prep
generate csr and key from input file

program is looking for input file named SUBJECT

add one or more subject lines to file for processing: e.g.
```
/C=US/ST=California/L=San Diego/O=My Company, Inc./OU=Development and Engineering/CN=hostname.and.catchy.domain.com
```  
it can also handle SAN requests by adding more FQDNs to the end separated by /
```
/C=US/ST=California/L=San Diego/O=My Company, Inc./OU=Development and Engineering/CN=hostname.and.catchy.domain.com/othername.and.catchy.domain.com
``` 
output will be a csr and private key for each SUBJECT file entry
