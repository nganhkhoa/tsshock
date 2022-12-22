package pedersen

import (
	"crypto/rand"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

var benchParams *Parameters
var benchN *safenum.Modulus

func init() {
	p, _ := new(safenum.Nat).SetHex("D08769E92F80F7FDFB85EC02AFFDAED0FDE2782070757F191DCDC4D108110AC1E31C07FC253B5F7B91C5D9F203AA0572D3F2062A3D2904C535C6ACCA7D5674E1C2640720E762C72B66931F483C2D910908CF02EA6723A0CBBB1016CA696C38FEAC59B31E40584C8141889A11F7A38F5B17811D11F42CD15B8470F11C6183802B")
	q, _ := new(safenum.Nat).SetHex("C21239C3484FC3C8409F40A9A22FABFFE26CA10C27506E3E017C2EC8C4B98D7A6D30DED0686869884BE9BAD27F5241B7313F73D19E9E4B384FABF9554B5BB4D517CBAC0268420C63D545612C9ADABEEDF20F94244E7F8F2080B0C675AC98D97C580D43375F999B1AC127EC580B89B2D302EF33DD5FD8474A241B0398F6088CA7")
	s, _ := new(safenum.Nat).SetHex("2A1023ADD5BEF3F3C2DCAF8B99713C18CF5BC42F38797BAFC808E5856F45E7EC51C450DA2B03171DBA0F0FA29025A7ED910A8B1BC13772BD79D4718A6DC618DE354D8F46378AC1BD6E2030AB761C4A2878F859C692823B60E5F4E4BB7BCD16DCECCBFBE65016DE88BB576A897E73F32456C07AD7DC61013C4A90FD509C79200A8D04310AD5338D32D861A73398677C1D3A2CBA958F9232B4E83AA4B133E7D1E694FF4615BE9F4E73B51C13F1193402CE36BFA0970C8B4C67920B5122B3B77DC3AC8F8FE92C7912649808F999309AE8B8641EA330B5E8BFFF8528FC8D85B84BD61E2FF5A261E80434444CC407CBA4D5FAE2D2587AF7624D2B99F4FF33640BA0F0")
	t, _ := new(safenum.Nat).SetHex("376A2C4A49B8C27F943059A358BCD65BCC0BAB1ABBBE368FFD004580A49EE795B4ECF85B2FB2A24969129E34E9E5D91503D11DE9D11F51538AC66A418B2E31463A55AAFAA29B645C2D04FBC829E3B55F95BFB0B5DE464ED0516DF28D36B4225B4050B80271E1AD8F11866E01FF83D40A06A7F7298FD96B210BE56AA4D3C0524E7372E371D0C6E52E043D2E1BF38E435ED85EB032FAC86C049E9FB8280847ABED9F2025FE03C7B8B8E32914238E3281BA17A2DB4CB2ACAD033442EF55E1BF2E4A741A961833CBE87C8C751E8A59EF998528BA0658CB9342EEDBDF62894E4AE66414024361D916248801D2929326102081BB2F7AD1C57C55AE8038EE35CC2C9915")
	n := arith.ModulusFromFactors(p, q)
	benchN = n.Modulus
	benchParams = &Parameters{n: n, s: s, t: t}
}

// These exist to avoid optimization.
var resultBig *safenum.Nat
var resultBool bool

func BenchmarkPedersenCommit(b *testing.B) {
	b.StopTimer()
	x := sample.IntervalL(rand.Reader)
	y := sample.IntervalL(rand.Reader)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultBig = benchParams.Commit(x, y)
	}
}

func BenchmarkPedersenVerify(b *testing.B) {
	b.StopTimer()
	x := sample.IntervalL(rand.Reader)
	y := sample.IntervalL(rand.Reader)
	S := sample.ModN(rand.Reader, benchN)
	T := sample.ModN(rand.Reader, benchN)
	e := sample.IntervalL(rand.Reader)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultBool = benchParams.Verify(x, y, e, S, T)
	}
}
