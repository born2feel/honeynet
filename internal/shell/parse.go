package shell

import "strings"

// A tiny subset of POSIX sh grammar, enough for what bots actually send:
//
//	list     = pipeline { (";" | "&&" | "||" | "&") pipeline }
//	pipeline = command { "|" command }
//	command  = word { word } [ (">" | ">>") word ]
//
// Quotes and $VAR expansion are honoured. There is no globbing, subshells or
// command substitution: those are recorded verbatim and fail harmlessly.

type command struct {
	args     []string
	redirect string // file stdout goes to
	appendTo bool
}

type pipeline struct {
	op   string // operator that precedes this pipeline: "", ";", "&&", "||"
	cmds []command
}

type token struct {
	op   string // non-empty for operators
	word string
}

func tokenize(line string, env func(string) string) []token {
	var (
		toks   []token
		buf    strings.Builder
		inWord bool
		quote  rune
	)
	flush := func() {
		if inWord {
			toks = append(toks, token{word: buf.String()})
			buf.Reset()
			inWord = false
		}
	}
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				buf.WriteRune(r)
			}
		case quote == '"':
			switch {
			case r == '"':
				quote = 0
			case r == '\\' && i+1 < len(rs) && strings.ContainsRune(`"\$`, rs[i+1]):
				i++
				buf.WriteRune(rs[i])
			case r == '$':
				i = expand(rs, i, &buf, env)
			default:
				buf.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == '\\' && i+1 < len(rs):
			i++
			buf.WriteRune(rs[i])
			inWord = true
		case r == '$':
			i = expand(rs, i, &buf, env)
			inWord = true
		case r == ' ' || r == '\t' || r == '\r' || r == '\n':
			flush()
		case r == ';':
			flush()
			toks = append(toks, token{op: ";"})
		case r == '&' || r == '|':
			flush()
			if i+1 < len(rs) && rs[i+1] == r {
				toks = append(toks, token{op: string([]rune{r, r})})
				i++
			} else if r == '&' {
				toks = append(toks, token{op: ";"}) // background: treat as sequence
			} else {
				toks = append(toks, token{op: "|"})
			}
		case r == '>':
			// "2>" / "2>&1" / "&>" redirect stderr: we don't model stderr, drop them.
			fd := ""
			if inWord && (buf.String() == "1" || buf.String() == "2") {
				fd = buf.String()
				buf.Reset()
				inWord = false
			}
			flush()
			op := ">"
			if i+1 < len(rs) && rs[i+1] == '>' {
				op = ">>"
				i++
			}
			if i+1 < len(rs) && rs[i+1] == '&' { // >&1, >&2
				i += 2
				continue
			}
			if fd == "2" {
				op = "2>"
			}
			toks = append(toks, token{op: op})
		case r == '<':
			flush()
			toks = append(toks, token{op: "<"})
		default:
			buf.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return toks
}

// expand handles $NAME, ${NAME} and $? starting at rs[i] == '$'; returns the new index.
func expand(rs []rune, i int, buf *strings.Builder, env func(string) string) int {
	if i+1 >= len(rs) {
		buf.WriteRune('$')
		return i
	}
	if rs[i+1] == '{' {
		end := i + 2
		for end < len(rs) && rs[end] != '}' {
			end++
		}
		if end < len(rs) {
			buf.WriteString(env(string(rs[i+2 : end])))
			return end
		}
		buf.WriteRune('$')
		return i
	}
	if rs[i+1] == '?' {
		buf.WriteString(env("?"))
		return i + 1
	}
	end := i + 1
	for end < len(rs) && (rs[end] == '_' || rs[end] >= 'a' && rs[end] <= 'z' || rs[end] >= 'A' && rs[end] <= 'Z' || end > i+1 && rs[end] >= '0' && rs[end] <= '9') {
		end++
	}
	if end == i+1 {
		buf.WriteRune('$')
		return i
	}
	buf.WriteString(env(string(rs[i+1 : end])))
	return end - 1
}

func parse(line string, env func(string) string) []pipeline {
	var (
		out  []pipeline
		cur  = pipeline{}
		cmd  command
		toks = tokenize(line, env)
	)
	endCmd := func() {
		if len(cmd.args) > 0 {
			cur.cmds = append(cur.cmds, cmd)
		}
		cmd = command{}
	}
	endPipeline := func(nextOp string) {
		endCmd()
		if len(cur.cmds) > 0 {
			out = append(out, cur)
		}
		cur = pipeline{op: nextOp}
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.op {
		case "":
			cmd.args = append(cmd.args, t.word)
		case "|":
			endCmd()
		case ";", "&&", "||":
			endPipeline(t.op)
		case ">", ">>", "2>", "<":
			if i+1 < len(toks) && toks[i+1].op == "" {
				i++
				switch t.op {
				case ">", ">>":
					cmd.redirect = toks[i].word
					cmd.appendTo = t.op == ">>"
				case "<":
					cmd.args = append(cmd.args, toks[i].word) // close enough: most tools accept a file arg
				}
			}
		}
	}
	endPipeline("")
	return out
}
