# Smart Office Access Control Policy
# -----------------------------------------
# Purpose:
# This policy enforces Attribute-Based Access Control (ABAC) for smart office devices,
# specifically smart locks for meeting rooms and thermostats for temperature control.
# The policy determines access permissions based on user roles, device types,
# and contextual attributes such as time and location.
#
# ABAC Attributes:
# Subject Attributes: User roles (Employee, Visitor) and assigned locations.
# Object Attributes: Device types (Smart_Lock, Thermostat) and paired devices.
# Context Attributes: Time of day (working_hours, non_working_hours) and location.
#
# Policy Structure and Rules:
# Default Rule: Deny access unless explicitly allowed.
# Employee Access: Employees can access smart locks during working hours on their assigned floors.
# Visitor Access: Visitors can access smart locks if their paired device matches and it is within working hours.
# Thermostat Control: Employees can adjust thermostat settings on their assigned floors during working hours.
# working_hours_valid: Validates that the access attempt occurs during working hours.
# visitor_device_matches: Validates a visitor’s paired device using MAC address.

package app.abac_office

default allow := false

# Rule for an Employee to access a smart lock during working hours
allow if {
	data.user_attributes[input.user].role == "Employee"
	input.object.device_type == "Smart_Lock"
	working_hours_valid
	input.context.location == data.user_attributes[input.user].assigned_floor
}

# Rule for a Visitor to access a smart lock with a paired device during working hours
allow if {
	data.user_attributes[input.user].role == "Visitor"
	input.object.device_type == "Smart_Lock"
	visitor_device_matches
	working_hours_valid
}

# Rule for an Employee to access a thermostat for temperature control during working hours
allow if {
	data.user_attributes[input.user].role == "Employee"
	input.object.device_type == "Thermostat"
	working_hours_valid
	input.context.location == data.user_attributes[input.user].assigned_floor
}

# Check if the access attempt is during working hours
working_hours_valid if {
	input.context.time_of_day == "working_hours"
}

# Ensure the Visitor's paired device matches
visitor_device_matches if {
	data.device_pairing[input.object.device_id].mac_address == input.visitor_mac_address
}

# Test Cases
# -----------------------------------------
# Test Case 1: Employee accessing smart lock during working hours
# {
#   "user": "David",
#   "object": {"device_type": "Smart_Lock"},
#   "context": {"time_of_day": "working_hours", "location": "floor_3"}
# }
# Expected Result: true: Authorized Employee
# Test Case 2: Visitor accessing smart lock with paired device
# {
#   "user": "Emma",
#   "object": {"device_type": "Smart_Lock", "device_id": "device_001"},
#   "visitor_mac_address": "11:22:33:44:55:66",
#   "context": {"time_of_day": "working_hours"}
# }
# Expected Result: true: Visitor with Paired Device
# Test Case 3: Visitor accessing smart lock without paired device
# {
#   "user": "Frank",
#   "object": {"device_type": "Smart_Lock", "device_id": "device_002"},
#   "visitor_mac_address": "77:88:99:AA:BB:CC",
#   "context": {"time_of_day": "working_hours"}
# }
# Expected Result: false: Unpaired Device
# Test Case 4: Employee accessing thermostat during working hours
# {
#   "user": "David",
#   "object": {"device_type": "Thermostat"},
#   "context": {"time_of_day": "working_hours", "location": "floor_3"}
# }
# Expected Result: true: Authorized Thermostat Access
# Test Case 5: Visitor attempting to access thermostat
# {
#   "user": "Emma",
#   "object": {"device_type": "Thermostat"},
#   "context": {"time_of_day": "working_hours", "location": "floor_3"}
# }
# Expected Result: false: Visitors are not authorized
# Test Case 6: Employee accessing smart lock outside of working hours
# {
#   "user": "David",
#   "object": {"device_type": "Smart_Lock"},
#   "context": {"time_of_day": "non_working_hours", "location": "floor_3"}
# }
# Expected Result: false: Unauthorized Time of Day
# Test Case 7: Visitor accessing smart lock during non-working hours (invalid time)
# {
#   "user": "Emma",
#   "object": {"device_type": "Smart_Lock", "device_id": "device_001"},
#   "visitor_mac_address": "11:22:33:44:55:66",
#   "context": {"time_of_day": "non_working_hours"}
# }
# Expected Result: false: Unauthorized Time of Day
# Test Case 8: Employee attempting thermostat access on an unassigned floor
# {
#   "user": "David",
#   "object": {"device_type": "Thermostat"},
#   "context": {"time_of_day": "working_hours", "location": "floor_2"}
# }
# Expected Result: false: Unauthorized Floor
