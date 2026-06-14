package workout

import (
	"context"
	"errors"
	"fmt"

	"github.com/tsatsarisg/go-fit/internal/user"
)

// Store is the workout bounded context's persistence port. Defined on the
// consumer side (D7) so the service layer owns the contract; the postgres
// implementation satisfies it. Swapping adapters (e.g. an in-memory fake for
// tests) requires no change to this file.
type Store interface {
	CreateWorkout(ctx context.Context, workout *Workout) (*Workout, error)
	GetWorkoutByID(ctx context.Context, id WorkoutID) (*Workout, error)
	UpdateWorkout(ctx context.Context, id WorkoutID, userID user.UserID, patch WorkoutPatch) (*Workout, error)
	// DeleteWorkout enforces ownership in SQL (id + user_id) and returns
	// ErrNotFound when the row doesn't exist, ErrForbidden when it does
	// but belongs to someone else.
	DeleteWorkout(ctx context.Context, id WorkoutID, userID user.UserID) error
}

// Domain-level sentinels. Callers use errors.Is to map to the appropriate
// HTTP status:
//   - ErrNotFound:   "workout id doesn't exist"               → 404
//   - ErrForbidden:  "row exists but belongs to another user" → 403
//   - ErrValidation: "aggregate / patch invariants violated"   → 400
var (
	ErrNotFound   = errors.New("workout not found")
	ErrForbidden  = errors.New("forbidden")
	ErrValidation = errors.New("validation failed")
)

func wrapValidation(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrValidation, err)
}

// Service is the workout bounded context's application service. Owns the
// orchestration previously tangled into handlers: validate command, build /
// mutate aggregate, persist. Transport depends on Service, not Store.
type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

// CreateWorkoutCommand is the input to Service.Create. UserID is set by the
// service from the authenticated principal — never from the request body —
// so a client cannot forge ownership by sending user_id in the payload.
type CreateWorkoutCommand struct {
	UserID          user.UserID
	Title           string
	Description     string
	DurationMinutes int
	CaloriesBurned  int
	Entries         []WorkoutEntry
}

func (s *Service) Create(ctx context.Context, cmd CreateWorkoutCommand) (*Workout, error) {
	w := &Workout{
		UserID:          cmd.UserID,
		Title:           cmd.Title,
		Description:     cmd.Description,
		DurationMinutes: cmd.DurationMinutes,
		CaloriesBurned:  cmd.CaloriesBurned,
		Entries:         cmd.Entries,
	}
	if err := w.Validate(); err != nil {
		return nil, wrapValidation(err)
	}
	return s.store.CreateWorkout(ctx, w)
}

// Get returns the workout only if it exists and belongs to userID. A workout
// owned by another user yields ErrForbidden rather than the row — without this
// the read path was a BOLA/IDOR hole (any authenticated caller could fetch any
// workout by guessing its id), even though Create/Update/Delete already gate on
// ownership. We load-then-authorize here so the policy sits next to the other
// ownership rules; at this scale the extra row read is noise.
func (s *Service) Get(ctx context.Context, id WorkoutID, userID user.UserID) (*Workout, error) {
	w, err := s.store.GetWorkoutByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if w.UserID != userID {
		return nil, ErrForbidden
	}
	return w, nil
}

// UpdateWorkoutCommand carries the patch plus the acting user's id so the
// store can enforce ownership in its WHERE clause.
type UpdateWorkoutCommand struct {
	WorkoutID WorkoutID
	UserID    user.UserID
	Patch     WorkoutPatch
}

func (s *Service) Update(ctx context.Context, cmd UpdateWorkoutCommand) (*Workout, error) {
	if err := cmd.Patch.Validate(); err != nil {
		return nil, wrapValidation(err)
	}
	return s.store.UpdateWorkout(ctx, cmd.WorkoutID, cmd.UserID, cmd.Patch)
}

func (s *Service) Delete(ctx context.Context, workoutID WorkoutID, userID user.UserID) error {
	return s.store.DeleteWorkout(ctx, workoutID, userID)
}
