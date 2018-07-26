package grect

import (
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

type Rect struct {
	Min, Max []float64
}

func (r Rect) String() string {
	diff := len(r.Min) != len(r.Max)
	if !diff {
		for i := 0; i < len(r.Min); i++ {
			if r.Min[i] != r.Max[i] {
				diff = true
				break
			}
		}
	}
	var buf []byte
	buf = append(buf, '[')
	for i, v := range r.Min {
		if i > 0 {
			buf = append(buf, ' ')
		}
		buf = append(buf, strconv.FormatFloat(v, 'f', -1, 64)...)
	}
	if diff {
		buf = append(buf, ']', ',', '[')
		for i, v := range r.Max {
			if i > 0 {
				buf = append(buf, ' ')
			}
			buf = append(buf, strconv.FormatFloat(v, 'f', -1, 64)...)
		}
	}
	buf = append(buf, ']')
	return string(buf)
}

func normalize(min, max []float64) (nmin, nmax []float64) {
	if len(max) == 0 {
		return min, min
	} else if len(max) != len(min) {
		if len(max) < len(min) {
			max = append(max, min[len(max):]...)
		} else if len(min) < len(max) {
			min = append(min, max[len(min):]...)
		}
	}
	match := true
	for i := 0; i < len(min); i++ {
		if min[i] != max[i] {
			if match {
				match = false
			}
			if min[i] > max[i] {
				min[i], max[i] = max[i], min[i]
			}
		}
	}
	if match {
		return min, min
	}
	return min, max
}

func Get(s string) Rect {
	var i int
	var ws bool
	var min, max []float64
	for ; i < len(s); i++ {
		switch s[i] {
		default:
			continue
		case ' ', '\t', '\r', '\n':
			ws = true
			continue
		case '[':
			min, max, i = getRect(s, i)
		case '{':
			min, max, i = getGeoJSON(s, i)
		case 0x00, 0x01:
			if !ws {
				//		return parseWKB(s, i)
			}
		case 'p', 'P', 'l', 'L', 'm', 'M', 'g', 'G':
			min, max, i = getWKT(s, i)
		}
		break
	}
	min, max = normalize(min, max)
	return Rect{Min: min, Max: max}
}

func getRect(s string, i int) (min, max []float64, ri int) {
	a := s[i:]
	parts := strings.Split(a, ",")
	for i := 0; i < len(parts) && i < 2; i++ {
		part := parts[i]
		if len(part) > 0 && (part[0] <= ' ' || part[len(part)-1] <= ' ') {
			part = strings.TrimSpace(part)
		}
		if len(part) >= 2 && part[0] == '[' && part[len(part)-1] == ']' {
			pieces := strings.Split(part[1:len(part)-1], " ")
			if i == 0 {
				min = make([]float64, 0, len(pieces))
			} else {
				max = make([]float64, 0, len(pieces))
			}
			for j := 0; j < len(pieces); j++ {
				piece := pieces[j]
				if piece != "" {
					n, _ := strconv.ParseFloat(piece, 64)
					if i == 0 {
						min = append(min, n)
					} else {
						max = append(max, n)
					}
				}
			}
		}
	}

	// normalize
	if len(parts) == 1 {
		max = min
	} else {
		min, max = normalize(min, max)
	}

	return min, max, len(s)
}

func union(min1, max1, min2, max2 []float64) (umin, umax []float64) {
	for i := 0; i < len(min1) || i < len(min2); i++ {
		if i >= len(min1) {
			// just copy min2
			umin = append(umin, min2[i])
			umax = append(umax, max2[i])
		} else if i >= len(min2) {
			// just copy min1
			umin = append(umin, min1[i])
			umax = append(umax, max1[i])
		} else {
			if min1[i] < min2[i] {
				umin = append(umin, min1[i])
			} else {
				umin = append(umin, min2[i])
			}
			if max1[i] > max2[i] {
				umax = append(umax, max1[i])
			} else {
				umax = append(umax, max2[i])
			}
		}
	}
	return umin, umax
}

func getWKT(s string, i int) (min, max []float64, ri int) {
	switch s[i] {
	default:
		for ; i < len(s); i++ {
			if s[i] == ',' {
				return nil, nil, i
			}
			if s[i] == '(' {
				return getWKTAny(s, i)
			}
		}
		return nil, nil, i
	case 'g', 'G':
		if len(s)-i < 18 {
			return nil, nil, i
		}
		return getWKTGeometryCollection(s, i+18)
	}
}

func getWKTAny(s string, i int) (min, max []float64, ri int) {
	min, max = make([]float64, 0, 4), make([]float64, 0, 4)
	var depth int
	var ni int
	var idx int
loop:
	for ; i < len(s); i++ {
		switch s[i] {
		default:
			if ni == 0 {
				ni = i
			}
		case '(':
			depth++
		case ')', ' ', '\t', '\r', '\n', ',':
			if ni != 0 {
				n, _ := strconv.ParseFloat(s[ni:i], 64)
				if idx >= len(min) {
					min = append(min, n)
					max = append(max, n)
				} else {
					if n < min[idx] {
						min[idx] = n
					} else if n > max[idx] {
						max[idx] = n
					}
				}
				idx++
				ni = 0
			}
			switch s[i] {
			case ')':
				idx = 0
				depth--
				if depth == 0 {
					i++
					break loop
				}
			case ',':
				idx = 0
			}
		}
	}
	return min, max, i
}

func getWKTGeometryCollection(s string, i int) (min, max []float64, ri int) {
	var depth int
	for ; i < len(s); i++ {
		if s[i] == ',' || s[i] == ')' {
			// do not increment the index
			return nil, nil, i
		}
		if s[i] == '(' {
			depth++
			i++
			break
		}
	}
next:
	for ; i < len(s); i++ {
		switch s[i] {
		case 'p', 'P', 'l', 'L', 'm', 'M', 'g', 'G':
			var min2, max2 []float64
			min2, max2, i = getWKT(s, i)
			min, max = union(min, max, min2, max2)
			for ; i < len(s); i++ {
				if s[i] == ',' {
					i++
					goto next
				}
				if s[i] == ')' {
					i++
					goto done
				}
			}
		case ' ', '\t', '\r', '\n':
			continue
		default:
			goto end_early
		}
	}
end_early:
	// just balance the parens
	for ; i < len(s); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
			if depth == 0 {
				i++
				break
			}
		}
	}
done:
	return min, max, i
}
func getGeoJSON(s string, i int) (min, max []float64, ri int) {
	json := s[i:]
	switch gjson.Get(json, "type").String() {
	default:
		min, max = getMinMaxBrackets(gjson.Get(json, "coordinates").Raw)
	case "Feature":
		min, max, _ = getGeoJSON(gjson.Get(json, "geometry").String(), 0)
	case "FeatureCollection":
		for _, json := range gjson.Get(json, "features").Array() {
			nmin, nmax, _ := getGeoJSON(json.String(), 0)
			min, max = union(min, max, nmin, nmax)
		}
	case "GeometryCollection":
		for _, json := range gjson.Get(json, "geometries").Array() {
			nmin, nmax, _ := getGeoJSON(json.String(), 0)
			min, max = union(min, max, nmin, nmax)
		}
	}
	return min, max, len(json)
}

func getMinMaxBrackets(s string) (min, max []float64) {
	var ni int
	var idx int
	for i := 0; i < len(s); i++ {
		switch s[i] {
		default:
			if ni == 0 {
				ni = i
			}
		case '[', ',', ']', ' ', '\t', '\r', '\n':
			if ni > 0 {
				n, _ := strconv.ParseFloat(s[ni:i], 64)
				if idx >= len(min) {
					min = append(min, n)
					max = append(max, n)
				} else {
					if n < min[idx] {
						min[idx] = n
					} else if n > max[idx] {
						max[idx] = n
					}
				}
				ni = 0
				idx++
			}
			if s[i] == ']' {
				idx = 0
			}

		}
	}

	return
}
