// Code generated by "stringer -type=Class"; DO NOT EDIT.

package dnsmsg

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[IN-1]
	_ = x[CS-2]
	_ = x[CH-3]
	_ = x[HS-4]
}

const _Class_name = "INCSCHHS"

var _Class_index = [...]uint8{0, 2, 4, 6, 8}

func (i Class) String() string {
	i -= 1
	if i >= Class(len(_Class_index)-1) {
		return "Class(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _Class_name[_Class_index[i]:_Class_index[i+1]]
}
