package keeperv1

import (
	"github.com/blang/semver"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"gitlab.com/thorchain/thornode/common/cosmos"
)

// GetVersionWithCtx returns the version with the given context,
// and returns true if the version was found in the store
func (k KVStore) GetVersionWithCtx(ctx cosmos.Context) (semver.Version, bool) {
	// InfiniteGasMeter allows calls without affecting gas and consensus
	ctx = ctx.WithGasMeter(sdk.NewInfiniteGasMeter())
	key := k.GetKey(ctx, prefixVersion, "")
	store := ctx.KVStore(k.storeKey)
	val := store.Get([]byte(key))
	if val == nil {
		return semver.Version{}, false
	}
	return semver.MustParse(string(val)), true
}

// GetVersionWithCtxt stores the version
func (k KVStore) SetVersionWithCtx(ctx cosmos.Context, v semver.Version) {
	key := k.GetKey(ctx, prefixVersion, "")
	store := ctx.KVStore(k.storeKey)
	store.Set([]byte(key), []byte(v.String()))
}
