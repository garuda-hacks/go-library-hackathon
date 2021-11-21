package jwt

import (
	"testing"

	"github.com/Masterminds/goutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Users struct {
	Name, Phone, Email string
}

func TestNewJWTMaker(t *testing.T) {
	randomString, _ := goutils.RandomAlphabetic(32)
	maker, err := NewJWTMaker(randomString, "", 10)
	require.NoError(t, err)
	require.NotEmpty(t, maker)
}

func TestNewJWTMakerInvalidKey(t *testing.T) {
	maker, err := NewJWTMaker("123", "", 10)
	require.Error(t, err)
	require.Nil(t, maker)
}

func TestInfo_CreateToken(t *testing.T) {
	var user = Users{
		Name:  "test",
		Phone: "62831231823",
		Email: "kank.burhan@gmail.com",
	}

	randomString, _ := goutils.RandomAlphabetic(32)
	maker, err := NewJWTMaker(randomString, "", 10)
	require.NoError(t, err)

	token, err := maker.CreateToken(user)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err := maker.VerifyToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	require.True(t, payload.Valid)
}

func TestInvalidJWTToken(t *testing.T) {
	var user = Users{
		Name:  "test",
		Phone: "62831231823",
		Email: "kank.burhan@gmail.com",
	}
	randomString, _ := goutils.RandomAlphabetic(32)
	maker, err := NewJWTMaker(randomString, "", 10)
	require.NoError(t, err)

	token, err := maker.CreateToken(user)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	randomOthers, _ := goutils.RandomAlphabetic(32)
	maker, err = NewJWTMaker(randomOthers, "", 10)
	require.NoError(t, err)

	payload, err := maker.VerifyToken(token)
	require.False(t, payload.Valid)
	require.Error(t, err)

	require.Error(t, ErrExpiredToken)
}

func TestStripBearerPrefixFromTokenString(t *testing.T) {
	var assert = assert.New(t)

	var token = "bearer 123"
	rsp, err := StripBearerPrefixFromTokenString(token)
	assert.Equal(nil, err)
	assert.Equal("123", rsp, "Test Token lower bearer1")

	token = "Bearer 123"
	rsp, err = StripBearerPrefixFromTokenString(token)
	assert.Equal(nil, err)
	assert.Equal("123", rsp, "Test Token upper Bearer")

	token = "BEARER 123"
	rsp, err = StripBearerPrefixFromTokenString(token)
	assert.Equal(nil, err)
	assert.Equal("123", rsp, "Test Token all upper Bearer")

	token = "BeArEr 123"
	rsp, err = StripBearerPrefixFromTokenString(token)
	assert.Equal(nil, err)
	assert.Equal("123", rsp, "Test Token all upper lower Bearer")
}
