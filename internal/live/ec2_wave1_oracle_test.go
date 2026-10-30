// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package live

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWave1EC2OracleOutputMatchesFrozenKeys pins the frozen satellite key
// lists to the vendored in-tree oracle output: every kind+key line in
// testdata/wave1-ec2-oracle.txt (the owner's independent Scanner.Scan
// re-execution) must appear exactly once in the union of the parity test's 21
// resource/relationship keys and the gap test's 4 posture keys, and vice
// versa. The two sides are independent transcriptions of two separate oracle
// runs, so a transcription drift on either side fails here instead of passing
// silently. Executing the oracle itself still lives in the eshu repository
// and binds the later in-tree-deletion gate.
func TestWave1EC2OracleOutputMatchesFrozenKeys(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wave1-ec2-oracle.txt"))
	if err != nil {
		t.Fatal(err)
	}
	type oracleEntry struct {
		index int
		key   string
	}
	var entries []oracleEntry
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		index, kind, key, err := splitOracleLine(line)
		if err != nil {
			t.Fatalf("unparsable oracle line %q: %v", line, err)
		}
		if index != len(entries) {
			t.Fatalf("oracle line %d out of order: %q", len(entries), line)
		}
		entries = append(entries, oracleEntry{index: index, key: kind + "\x00" + key})
	}
	if len(entries) != len(wave1EC2OracleFrozenKeys) {
		t.Fatalf("oracle entry count = %d, want %d", len(entries), len(wave1EC2OracleFrozenKeys))
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if !wave1EC2OracleFrozenSet[entry.key] {
			t.Errorf("oracle fact %q matches no frozen satellite key", entry.key)
		}
		seen[entry.key] = true
	}
	for _, key := range wave1EC2OracleFrozenKeys {
		if !seen[key] {
			t.Errorf("frozen satellite key %q matches no oracle fact", key)
		}
	}
}

func splitOracleLine(line string) (index int, kind, key string, err error) {
	fields := strings.Fields(line)
	if len(fields) != 4 || fields[0] != "ORACLE" {
		return 0, "", "", errOracleLine(line)
	}
	for _, c := range fields[1] {
		if c < '0' || c > '9' {
			return 0, "", "", errOracleLine(line)
		}
		index = index*10 + int(c-'0')
	}
	kind, ok := strings.CutPrefix(fields[2], "kind=")
	if !ok {
		return 0, "", "", errOracleLine(line)
	}
	key, ok = strings.CutPrefix(fields[3], "key=")
	if !ok || kind == "" || key == "" {
		return 0, "", "", errOracleLine(line)
	}
	return index, kind, key, nil
}

func errOracleLine(line string) error {
	return &oracleLineError{line: line}
}

type oracleLineError struct {
	line string
}

func (e *oracleLineError) Error() string {
	return "malformed oracle line: " + e.line
}

// wave1EC2OracleFrozenKeys is the union of the frozen lists in
// TestWave1EC2ExistingParityAgainstInTreeOracle (21 resource/relationship
// keys) and TestWave1EC2GapParityAgainstInTreeOracle (4 posture keys),
// transcribed here so this test cross-checks both against the vendored oracle
// output instead of trusting either transcription alone.
var wave1EC2OracleFrozenKeys = []string{ // Frozen parity vectors: test data.
	"aws_resource\x0017f471132bc29990b36837ab30c388f7b8206c3cf8701bfa6ea126f0b365a2f8",
	"aws_resource\x00adaa5ade324f15fb97f3d500d7bd212d69fbb65a36204c041fb601e75fe768de",
	"aws_relationship\x00c4fed8da5d0bc3f7355074189f3e19de685c50434418e780389f136bf6c4b03e",
	"aws_resource\x0028c160045a039e8b569ec379b49b8e7e61700957aa2957fec7444db86561cbc9",
	"aws_relationship\x006f8ff0f2bb1de0f9733ddb17e55f05cce5af8a181f6325314ba1aabad88dc400",
	"aws_resource\x00b621175c9e3822d9a775125e8623fa2cf513d1ab3b26f5171b52104035045945",
	"aws_relationship\x009fc143989fdb07c5e4aff31764f22f6b4098ac4da860770f38077ea5f9f703fd",
	"aws_security_group_rule\x00d4373b5d54f28e24d86164a999d1b4413957f5725e869980ef33d1ae57c88c8b",
	"aws_resource\x00a99604f42609e05d67cb38e197d1f5160afecd73ba452d3660eaf8be3bc6a480",
	"aws_relationship\x006e8c480b48b9c514b1b29e4b6f6d482dcefa57cb959367912775c7685a9b6979",
	"aws_security_group_rule\x00828bdb8d4b4842d4c75dc70aae4fb53f6d658ec6a957f8322fbebdeed5e2e3dd",
	"aws_resource\x005b84b35dbd6bdf089315c426b489cb4f84b0c5f3f4275da81648a66e084f3bb5",
	"aws_relationship\x00f4b077abca9ba48f8b7d3c1fc8be86ff1c8cd3236a43ddc675e0bba959e9779f",
	"aws_security_group_rule\x0031dc36fc0dd0fee06cbadcdb51fffbe36932a1a178731c638044840aebe7e126",
	"aws_resource\x003e70715b86c89a8ab22d98de9321da98fa27558a5f28fe8056fa3dee9b849a0c",
	"aws_relationship\x00f4e7f9024d13785a7abc69fb54ce4d5091fb07d40cd6dfc3a6721984dc695678",
	"aws_relationship\x0068e87405a93f23ca4dc02e5564f149d7b78fa8f732670d3f147507514d36b080",
	"aws_relationship\x005e4b5ae77652cee885e3e99f5c9b4bcc74c6d15475b425e1a8d5842fb3129800",
	"aws_relationship\x0022614ae83911c01335f2fa516dece9fd6f3f82be7c7ddc2778cecaf561bb9168",
	"ec2_instance_posture\x00bccfe99d717602531c9eeb0ac1889236f16e0924ffc40b66ff8fefee72e81b04",
	"aws_resource\x00b3467e6df86a6c7484e93d8874df7dcff3c416e71487d6b3f663dafe22fec5ad",
	"aws_relationship\x0032b57dbc3bd9c05ff77e9ed8ba6c4ef9d878426526c7f1005a34e6f0a3531e5f",
	"aws_resource\x0083cdc1f7260f45a402b835c108b3c6ca6d9af7cfc4f3cbc2b8635f486ffbdb52",
	"aws_resource\x00347ea629dbebba6b9a7af6aa45c299bfd922bbda9232097b40528d7f07dfd905",
	"aws_relationship\x0036648f191e897893177aa08e14713af8d659095e49ec09a3b07f09f86f2abf20",
}

var wave1EC2OracleFrozenSet = func() map[string]bool { // Derived once from the frozen vectors above.
	set := make(map[string]bool, len(wave1EC2OracleFrozenKeys))
	for _, key := range wave1EC2OracleFrozenKeys {
		set[key] = true
	}
	return set
}()
