package health

import (
	"log"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNew_InitialisesFieldsCorrectly(t *testing.T) {
	backoff := 5 * time.Second
	window := 10 * time.Second
	threshold := 2
	logger := log.Default()

	ht := New(backoff, window, threshold, logger)
	assert.NotNil(t, ht)

	// Observable: not unhealthy initially
	assert.False(t, ht.IsUnhealthy())

	// With threshold 2, one failure does not trip
	assert.False(t, ht.RecordFailure())
	assert.False(t, ht.IsUnhealthy())

	// Second failure trips
	assert.True(t, ht.RecordFailure())
	assert.True(t, ht.IsUnhealthy())
}

func TestRecordFailure_UnderThresholdDoesNotTrip_AtThresholdTrips(t *testing.T) {
	ht := New(100*time.Millisecond, 0, 3, log.Default())

	assert.False(t, ht.RecordFailure())
	assert.False(t, ht.IsUnhealthy())
	assert.False(t, ht.RecordFailure())
	assert.False(t, ht.IsUnhealthy())
	assert.True(t, ht.RecordFailure()) // third trips
	assert.True(t, ht.IsUnhealthy())
}

func TestRecordFailure_WindowReset(t *testing.T) {
	window := 50 * time.Millisecond
	ht := New(time.Second, window, 2, log.Default())

	ht.RecordFailure()
	assert.False(t, ht.IsUnhealthy())

	// Wait for window to elapse; next RecordFailure should reset counter and only count as 1
	time.Sleep(window + 10*time.Millisecond)
	ht.RecordFailure()
	assert.False(t, ht.IsUnhealthy()) // only 1 in new window

	// One more trips
	assert.True(t, ht.RecordFailure())
	assert.True(t, ht.IsUnhealthy())
}

func TestIsUnhealthy_TrueWhileInBackoff_FalseAfterExpiry(t *testing.T) {
	backoff := 50 * time.Millisecond
	ht := New(backoff, 0, 1, log.Default())

	ht.RecordFailure()
	assert.True(t, ht.IsUnhealthy())

	time.Sleep(backoff + 20*time.Millisecond)
	assert.False(t, ht.IsUnhealthy())
}

func TestRecordFailure_NegativeThresholdNeverTrips(t *testing.T) {
	ht := New(time.Second, 0, -1, log.Default())

	for i := 0; i < 100; i++ {
		assert.False(t, ht.RecordFailure())
		assert.False(t, ht.IsUnhealthy())
	}
}

func TestRecordFailure_ZeroThresholdFirstFailureTrips(t *testing.T) {
	ht := New(100*time.Millisecond, 0, 0, log.Default())

	// threshold 0: "first" failure trips (count >= 0 after first increment)
	assert.True(t, ht.RecordFailure())
	assert.True(t, ht.IsUnhealthy())
}

func TestRecordFailure_ConcurrentNoRace(t *testing.T) {
	ht := New(10*time.Millisecond, 5*time.Millisecond, 1000, log.Default())

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ht.RecordFailure()
				ht.IsUnhealthy()
			}
		}()
	}
	wg.Wait()
}
