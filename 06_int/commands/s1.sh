table_set_default ipv4_lpm drop
table_set_default int_table add_int_header 1
table_add ipv4_lpm ipv4_forward 10.0.1.1/32 => 00:00:0a:00:01:01 1
table_add ipv4_lpm ipv4_forward 10.0.2.2/32 => 00:01:0a:00:02:02 2
table_add ipv4_lpm ipv4_forward 10.0.3.0/24 => 00:00:00:03:01:00 3