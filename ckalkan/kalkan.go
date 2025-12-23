package ckalkan

// #cgo LDFLAGS: -ldl
// #include <dlfcn.h>
// #include <malloc.h>
//
// void force_defragment() {
//     malloc_trim(0);
// }
import "C"
import (
	"runtime"
	"sync"
)

// требуемая библиотека для KC
const dynamicLibs = "libkalkancryptwr-64.so"

// Client структура для взаимодействия с библиотекой KC
type Client struct {
	handler *libHandle
	mu      sync.Mutex
}

// NewKCClient возвращает клиента для работы с KC.
func NewClient() (*Client, error) {
	handler, err := getHandle(dynamicLibs)
	if err != nil {
		return nil, err
	}

	cli := &Client{
		handler: handler,
		mu:      sync.Mutex{},
	}

	return cli, nil
}

// forceDefragmentation принудительно дефрагментирует C heap
// Должно вызываться после каждой операции с C.malloc
func (cli *Client) forceDefragmentation() {
	// будет работать только под linux, как и сама либа
	C.force_defragment()

	// Принудительный сбор мусора Go для освобождения heap
	runtime.GC()
}
