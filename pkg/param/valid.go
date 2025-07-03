// https://parkjunwoo.com/microstral/pkg/param/valid.go
package param

type ValidFunc func(value string) (bool, error)

var validFuncs = make(map[uint32]ValidFunc)

// 함수 포인터 대신 함수 그 자체를 인자로 받도록 수정
func RegisterValidFunc(typ uint32, fn ValidFunc) {
	validFuncs[typ] = fn
}
