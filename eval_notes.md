# Eval notes

Check that there is no technos such as Traefik, Docker, Vagrant.
`sudo apt list --installed | grep -i -E 'traefik|docker|vagrant'`

The command that lists the open ports:
`sudo netstat -tulpn | grep LISTEN` or
`sudo ss -tulpn | grep LISTEN`

Use `openssl s_client -showcerts -connect the-git-server:443` to get the list of certificates being sent.

To clear iptables:
```bash
sudo iptables -P INPUT ACCEPT
sudo iptables -F
```
