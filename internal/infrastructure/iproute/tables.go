package iproute

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// Where ip reads the names of routing tables, as paths under the configuration
// root: the host's own file or, without one, the distribution's, and the
// drop-in files of both.
var (
	tableFiles = []string{"etc/iproute2/rt_tables", "usr/share/iproute2/rt_tables"}
	tableDirs  = []string{"etc/iproute2/rt_tables.d", "usr/share/iproute2/rt_tables.d"}
)

// builtinTables are the tables ip names without any configuration.
var builtinTables = map[string]int{"unspec": 0, "default": 253, "main": 254, "local": 255}

// tableNames resolves the table names ip prints to their ids: a node may name
// the agent's tables, and ip then prints the name — the tables must still be
// recognised as the agent's. The files are read at the first name that is not
// a number or a builtin, once per listing: most nodes name no table, and a
// name added since the last listing must resolve.
type tableNames struct {
	conf fs.FS
	ids  map[string]int
}

// id returns the id of a table as ip printed it; ok is false for a name no
// file defines.
func (t *tableNames) id(name string) (id int, ok bool, err error) {
	if id, err := strconv.Atoi(name); err == nil {
		return id, true, nil
	}
	if id, ok := builtinTables[name]; ok {
		return id, true, nil
	}
	if t.ids == nil {
		if t.ids, err = readTableNames(t.conf); err != nil {
			return 0, false, fmt.Errorf("table names: %w", err)
		}
	}
	id, ok = t.ids[name]
	return id, ok, nil
}

// readTableNames reads every file ip reads; a missing one defines nothing.
// A name defined twice keeps its first id.
func readTableNames(conf fs.FS) (map[string]int, error) {
	var files []string
	for _, f := range tableFiles {
		if _, err := fs.Stat(conf, f); err == nil {
			files = append(files, f)
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	for _, dir := range tableDirs {
		dropIns, err := fs.Glob(conf, dir+"/*.conf")
		if err != nil {
			return nil, err
		}
		files = append(files, dropIns...)
	}

	ids := map[string]int{}
	for _, f := range files {
		data, err := fs.ReadFile(conf, f)
		if err != nil {
			return nil, err
		}
		parseTableNames(data, ids)
	}
	return ids, nil
}

// parseTableNames adds the "id name" lines of an rt_tables file to ids. Like
// ip, it takes the id in decimal or 0x-prefixed hex, and skips comments and
// lines it cannot read.
func parseTableNames(data []byte, ids map[string]int) {
	for line := range strings.Lines(string(data)) {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		id, err := parseTableID(fields[0])
		if err != nil {
			continue
		}
		if _, dup := ids[fields[1]]; !dup {
			ids[fields[1]] = id
		}
	}
}

func parseTableID(s string) (int, error) {
	base := 10
	if hex, ok := strings.CutPrefix(s, "0x"); ok {
		s, base = hex, 16
	}
	id, err := strconv.ParseUint(s, base, 32)
	return int(id), err
}
