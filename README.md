# iran_resolver
iran_resolver is a coredns plugin to generate hosts file for banned and sanctioned urls.
It's useful to create something liked https://shecan.ir/; A DNS server witch resolve banned and sanctioned urls with ur custom server ip

## config 
example:
```
iran_resolver {
    dns-to-check 78.157.42.101:53 10.202.10.202:53  # Reqiered

    sanction-search develop.403 electro
    ban-search 10.10.34.35
    
    pg_host 127.0.0.1 # Reqiered
    pg_port 5432 # default 5432
    pg_user postgres # Reqiered
    pg_password 123456789 # Reqiered
    pg_db 123456789 # Reqiered
    pg_schema public # default public
    
    pg_ssl off # default off => off/on
    pg_ssl_mode verify-ca 
    pg_ssl_root_cert PATH_TO_ROOT_CERT
    
    server_tag KEY_TAG1:VALUE_TA1G KEY_TAG2:VALUE_TAG2 # this tag will be attach to each founded domain (sanction/ ban) from this server
    
    ban_tag TAG_VALUE
    sanction_tag TAG_VALUE

    sanction-buffer-size 10
    ban-buffer-size 10
}
```