table_set_default ipv4_lpm drop
table_set_default int_table add_int_header 2
table_add ipv4_lpm ipv4_forward 10.0.2.2/32 => 00:00:0a:00:02:02 1
table_add ipv4_lpm ipv4_forward 10.0.0.0/16 => 00:00:00:01:02:00 2