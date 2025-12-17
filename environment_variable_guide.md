
## Variable
PRIMARY_VAULT_SERVER_FQDN_FULL="my_awesome_domain.com"

> **Locations Used:**
> $HOME/NETWORK_TOOLS/docker-compose.prod.yml<br>
> Where $HOME is the users home directory that houses the NETWORK_TOOLS Folder

### Used for

```bash
Example

https://${PRIMARY_VAULT_SERVER_FQDN_FULL}:8200 -> https://my_awesome_domain.com:8200

vault_production_node -> VAULT_ADDR

VAULT_ADDR is primarily a client variable used by vault CLI and SDKs to know where to talk to

https://developer.hashicorp.com/vault/docs/commands
https://developer.hashicorp.com/vault/tutorials/get-started/learn-cli
```
