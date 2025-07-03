package test

default allow := false

allow if {
	input.path == "/"
}
