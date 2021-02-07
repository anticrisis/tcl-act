package require example::cutil
package require example::alpha
package require beta

proc ::main {} {
    puts [example::cutil::crypto::pwhash "password"]

    example::alpha::hello1
    example::alpha::hello2

    beta::hello1
    beta::hello2

    # asset
    set f [open [dict get $::act::assets "assets/data.txt"] r]
    set data [read $f]
    close $f

    puts $data
}

#
# Skip the rest of the file if we are being sourced rather than run
# from tclsh on the command line. When sourced, argc and argv are not
# set. When loaded via `package require`, $argv0 is equal to the tail
# of the executable (usually tclsh).
#
if {![info exists argc]} {return}
if {[file tail [info nameofexecutable]] eq $argv0} {return}


::main
::act::cleanup
