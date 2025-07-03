package test

default allow := false

public_paths := {
	"/signin",
	"/signin-callback",
	"/signout",
	"/signout-callback",
	"/forgot",
}

authenticated_paths := {"/myinfo"}

is_guest if "Guest" in input.roles

is_admin if "Admin" in input.roles

public_access if input.path in public_paths

authenticated_access if {
	input.path in authenticated_paths
	not is_guest
}

admin_access if {
	startswith(input.path, "/users")
	is_admin
}

allow if public_access

allow if authenticated_access

allow if admin_access
