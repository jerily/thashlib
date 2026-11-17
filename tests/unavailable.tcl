if {[llength $argv]} {lappend auto_path [lindex $argv 0]}
package require thashlib 0.1.0
foreach command {
    {::thashlib::sha1 abc} {::thashlib::sha256 abc}
    {::thashlib::sha512 abc} {::thashlib::md5 abc}
    {::thashlib::hmac_sha256 key abc} {::thashlib::random_bytes 1}
} {
    if {![catch $command message options]} {error "expected OpenSSL failure: $command"}
    if {[dict get $options -errorcode] ne {THASHLIB OPENSSL}} {error $options}
}
if {[::thashlib::hex_encode [::thashlib::hex_decode 00AaFF]] ne "00aaff"} {
    error "hex conversions should work without an OpenSSL provider"
}
puts "OpenSSL provider failures reported correctly"
