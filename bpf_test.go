package bpf

import (
	"testing"
	"unsafe"
)

// These structs need to match their counterparts in bpf/simple_map.c.
type key struct {
	a uint32
	b uint32
}

func (k *key) GetDataPtr() uintptr {
	return uintptr(unsafe.Pointer(k))
}

type entry struct {
	valueA uint64
	valueB uint64
}

func (e *entry) GetDataPtr() uintptr {
	return uintptr(unsafe.Pointer(e))
}

func TestBpfMapOperations(t *testing.T) {
	file := "bpf/simple_map.o"
	sections := []string{"classifier"}
	sectionNameToFd := make(map[string]int)
	mapNameToFd := make(map[string]int)

	err1, err2 := BpfLoadProg(file, sections, sectionNameToFd, mapNameToFd)
	if err1 != nil {
		t.Fatal("err1:", err1)
	}
	if err2 != nil {
		t.Fatal("err2:", err2)
		t.Fail()
	}

	if len(sectionNameToFd) != 1 {
		t.Fail()
	}

	if len(mapNameToFd) != 1 {
		t.Fail()
	}

	myKey := key{111, 222}
	myEntry := entry{}

	// First lookup should fail (empty map).
	found, err := BpfMapLookupElem(mapNameToFd["map1"], &myKey, &myEntry)
	if err != nil {
		t.Log("err:", err)
		t.Fail()
	}
	if found {
		t.Fail()
	}

	// Add an entry to the map.
	myEntry.valueA = 8888
	myEntry.valueB = 9999
	updated, err := BpfMapUpdateElem(mapNameToFd["map1"], &myKey, &myEntry, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("Element should have been updated.")
	}

	// Now search the map and verify we get the correct data back.
	found, err = BpfMapLookupElem(mapNameToFd["map1"], &myKey, &myEntry)
	if err != nil {
		t.Log("err:", err)
		t.Fail()
	}
	if !found {
		t.Fail()
	}

	if myEntry.valueA != 8888 {
		t.Fail()
	}
	if myEntry.valueB != 9999 {
		t.Fail()
	}

	// Now delete the entry.
	deleted, err := BpfMapDeleteElem(mapNameToFd["map1"], &myKey)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("Key should have been deleted.")
	}

	// Verify that the key/entry is gone from the map.
	found, err = BpfMapLookupElem(mapNameToFd["map1"], &myKey, &myEntry)
	if err != nil {
		t.Log("err:", err)
		t.Fail()
	}
	if found {
		t.Fail()
	}

	// Add multiple entries to the map and verify that we can iterate over the map.
	updated, err = BpfMapUpdateElem(mapNameToFd["map1"], &myKey, &myEntry, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("Element should have been updated.")
	}

	myKey.a = 333
	myKey.b = 444
	myEntry.valueA = 6666
	myEntry.valueB = 7777
	updated, err = BpfMapUpdateElem(mapNameToFd["map1"], &myKey, &myEntry, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("Element should have been updated.")
	}

	var keys []key
	iKey := key{0, 0} // Start the iteration with a key that won't be found.
	var nextKey key

	for {
		found, err := BpfMapGetNextKey(mapNameToFd["map1"], &iKey, &nextKey)
		if err != nil {
			t.Log(err)
			break
		}

		if !found {
			break
		}

		keys = append(keys, nextKey)
		iKey = nextKey
	}

	if len(keys) != 2 {
		t.Log("Wrong number of entries in the map.")
		t.Fail()
	}
}
