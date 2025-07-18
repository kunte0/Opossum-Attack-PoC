# Base: https://github.com/dovecot/docker/blob/main/2.4.0/dovecot.conf

dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0

base_dir = /run/dovecot
state_dir = /run/dovecot

protocols = imap submission lmtp sieve

import_environment {
  USER_PASSWORD=%{env:USER_PASSWORD|default('password')}
  DOVEADM_PASSWORD=%{env:DOVEADM_PASSWORD|default('supersecret')}
}

mail_driver=maildir
mailbox_list_layout=index
mailbox_list_utf8=yes
mail_path=~/mail
mail_home=/srv/vmail/%{user|lower}
mail_utf8_extensions = yes

default_internal_user = vmail
default_login_user = vmail
default_internal_group = vmail

mail_uid = vmail
mail_gid = vmail


passdb static {
  password=%{env:USER_PASSWORD}
}

namespace inbox {
  inbox = yes
  separator = /
}

ssl_server {
  cert_file = /etc/dovecot/ssl/tls.crt
  key_file = /etc/dovecot/ssl/tls.key
}

mail_attribute {
  dict file {
    path = %{home}/dovecot-attributes
  }
}

log_path = /dev/stdout

imap_hibernate_timeout = 5s

mail_plugins {
  fts = yes
  fts_flatcurve = yes
  mail_log = yes
  notify = yes
}

mail_log_events = delete undelete expunge save copy mailbox_create mailbox_delete mailbox_rename flag_change

fts_autoindex = yes
fts_autoindex_max_recent_msgs = 999
fts_search_add_missing = yes
language_filters = normalizer-icu snowball stopwords

language_tokenizers = generic email-address
language_tokenizer_generic_algorithm = simple

language en {
  default = yes
  filters = lowercase snowball english-possessive stopwords
}

fts flatcurve {
  substring_search = yes
}

protocol imap {
  mail_plugins {
     imap_sieve = yes
     imap_filter_sieve = yes
  }
}

protocol lmtp {
   mail_plugins {
      sieve = yes
   }
}

service imap-login {
  process_min_avail = 1
  client_limit = 100
  inet_listener imap {
     port = 31143
  }
  inet_listener imaps {
     port = 31993
  }
}

service pop3-login {
  process_min_avail = 1
  client_limit = 100
  inet_listener pop3 {
     port = 31110
  }
  inet_listener pop3s {
     port = 31990
  }
}

service submission-login {
  process_min_avail = 1
  client_limit = 100
  inet_listener submission {
    port = 31587
  }
  inet_listener submissions {
    port = 31465
    ssl = yes
  }
}

service managesieve-login {
  process_min_avail = 1
  client_limit = 100
  inet_listener sieve {
    port = 34190
  }
}

service doveadm {
  inet_listener http {
    port = 8080
    ssl = yes
  }
}

service stats {
  process_min_avail = 1
  inet_listener http {
    port = 9090
    ssl = yes
  }
}

service lmtp {
   inet_listener lmtp-o {
     port = 31023
   }
   inet_listener lmtps {
     port = 31024
     ssl = yes
   }
}

doveadm_password = ${env:DOVEADM_PASSWORD}

event_exporter log {
   format = json
   time_format = rfc3339
}

metric auth_success {
  filter = (event=auth_request_finished AND success=yes)
}

metric auth_failure {
  filter = (event=auth_request_finished AND NOT success=yes)
  exporter = log
}

metric imap_command {
  filter = event=imap_command_finished
  group_by cmd_name {
    method discrete {
    }
  }
  group_by tagged_reply_state {
    method discrete {
    }
  }
}

metric smtp_command {
  filter = event=smtp_server_command_finished and protocol=submission
  group_by cmd_name {
     method discrete {
    }
  }
  group_by status_code {
     method discrete {
    }
  }
  group_by duration {
     method exponential {
       base = 10
       min_magnitude = 1
       max_magnitude = 5
    }
  }
}

metric lmtp_command {
  filter = event=smtp_server_command_finished and protocol=lmtp
  group_by cmd_name {
     method discrete {
    }
  }
  group_by status_code {
     method discrete {
    }
  }
  group_by duration {
     method exponential {
       base = 10
       min_magnitude = 1
       max_magnitude = 5
    }
  }
}

metric mail_delivery {
  filter = event=mail_delivery_finished
  group_by duration {
     method exponential {
       base = 10
       min_magnitude = 1
       max_magnitude = 5
     }
  }
}

!include_try conf.d/*.conf