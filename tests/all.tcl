if {[llength $argv]} {lappend auto_path [lindex $argv 0]}
set argv {}
package require thashlib 0.1.0
package require tcltest 2
::tcltest::configure -singleproc true -testdir [file dirname [info script]]
exit [::tcltest::runAllTests]
