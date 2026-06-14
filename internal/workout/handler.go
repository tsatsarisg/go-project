package workout

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/tsatsarisg/go-fit/internal/auth"
	"github.com/tsatsarisg/go-fit/internal/httpx"
)

type Handler struct {
	service *Service
	logger  *slog.Logger
}

func NewHandler(service *Service, logger *slog.Logger) *Handler {
	return &Handler{service: service, logger: logger}
}

// errorMapping centralizes workout-specific sentinel → HTTP mapping for the
// httpx.WriteStoreError helper.
var errorMapping = httpx.StoreErrorMapping{
	ResourceName: "Workout",
	NotFoundErr:  ErrNotFound,
	ForbiddenErr: ErrForbidden,
}

func writeValidationError(w http.ResponseWriter, err error) {
	httpx.WriteJson(w, http.StatusBadRequest, httpx.Envelope{"error": err.Error()})
}

func (wh *Handler) HandleGetWorkoutByID(w http.ResponseWriter, r *http.Request) {
	workoutID, err := httpx.ReadIdParam(r, "id")
	if err != nil {
		wh.logger.WarnContext(r.Context(), "read id param", slog.Any("err", err))
		httpx.WriteJson(w, http.StatusBadRequest, httpx.Envelope{"error": err.Error()})
		return
	}

	principal := auth.GetPrincipal(r)
	if principal.IsAnonymous() {
		httpx.WriteJson(w, http.StatusUnauthorized, httpx.Envelope{"error": "Unauthenticated"})
		return
	}

	workout, err := wh.service.Get(r.Context(), WorkoutID(workoutID), principal.ID)
	if err != nil {
		httpx.WriteStoreError(r.Context(), w, wh.logger, err, errorMapping, "Failed to retrieve workout")
		return
	}

	httpx.WriteJson(w, http.StatusOK, httpx.Envelope{"workout": workout})
}

type createWorkoutRequest struct {
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	DurationMinutes int            `json:"duration_minutes"`
	CaloriesBurned  int            `json:"calories_burned"`
	Entries         []WorkoutEntry `json:"entries"`
}

func (wh *Handler) HandleCreateWorkout(w http.ResponseWriter, r *http.Request) {
	principal := auth.GetPrincipal(r)
	if principal.IsAnonymous() {
		httpx.WriteJson(w, http.StatusUnauthorized, httpx.Envelope{"error": "Unauthenticated"})
		return
	}

	var req createWorkoutRequest
	if derr := httpx.DecodeJSONBody(w, r, &req); derr != nil {
		wh.logger.WarnContext(r.Context(), "decode create workout", slog.Any("err", derr))
		httpx.WriteDecodeError(w, derr)
		return
	}

	cmd := CreateWorkoutCommand{
		UserID:          principal.ID,
		Title:           req.Title,
		Description:     req.Description,
		DurationMinutes: req.DurationMinutes,
		CaloriesBurned:  req.CaloriesBurned,
		Entries:         req.Entries,
	}
	created, err := wh.service.Create(r.Context(), cmd)
	if err != nil {
		if errors.Is(err, ErrValidation) {
			writeValidationError(w, err)
			return
		}
		httpx.WriteStoreError(r.Context(), w, wh.logger, err, errorMapping, "Failed to create workout")
		return
	}
	httpx.WriteJson(w, http.StatusCreated, httpx.Envelope{"workout": created})
}

func (wh *Handler) HandleUpdateWorkout(w http.ResponseWriter, r *http.Request) {
	workoutID, err := httpx.ReadIdParam(r, "id")
	if err != nil {
		wh.logger.WarnContext(r.Context(), "read id param", slog.Any("err", err))
		httpx.WriteJson(w, http.StatusBadRequest, httpx.Envelope{"error": err.Error()})
		return
	}

	principal := auth.GetPrincipal(r)
	if principal.IsAnonymous() {
		httpx.WriteJson(w, http.StatusUnauthorized, httpx.Envelope{"error": "Unauthenticated"})
		return
	}

	var body struct {
		Title           *string         `json:"title"`
		Description     *string         `json:"description"`
		DurationMinutes *int            `json:"duration_minutes"`
		CaloriesBurned  *int            `json:"calories_burned"`
		Entries         *[]WorkoutEntry `json:"entries"`
	}

	if derr := httpx.DecodeJSONBody(w, r, &body); derr != nil {
		wh.logger.WarnContext(r.Context(), "decode update workout", slog.Any("err", derr))
		httpx.WriteDecodeError(w, derr)
		return
	}

	cmd := UpdateWorkoutCommand{
		WorkoutID: WorkoutID(workoutID),
		UserID:    principal.ID,
		Patch: WorkoutPatch{
			Title:           body.Title,
			Description:     body.Description,
			DurationMinutes: body.DurationMinutes,
			CaloriesBurned:  body.CaloriesBurned,
			Entries:         body.Entries,
		},
	}

	updated, err := wh.service.Update(r.Context(), cmd)
	if err != nil {
		if errors.Is(err, ErrValidation) {
			writeValidationError(w, err)
			return
		}
		httpx.WriteStoreError(r.Context(), w, wh.logger, err, errorMapping, "Failed to update workout")
		return
	}

	httpx.WriteJson(w, http.StatusOK, httpx.Envelope{"workout": updated})
}

func (wh *Handler) HandleDeleteWorkout(w http.ResponseWriter, r *http.Request) {
	workoutID, err := httpx.ReadIdParam(r, "id")
	if err != nil {
		wh.logger.WarnContext(r.Context(), "read id param", slog.Any("err", err))
		httpx.WriteJson(w, http.StatusBadRequest, httpx.Envelope{"error": err.Error()})
		return
	}

	principal := auth.GetPrincipal(r)
	if principal.IsAnonymous() {
		httpx.WriteJson(w, http.StatusUnauthorized, httpx.Envelope{"error": "Unauthenticated"})
		return
	}

	if err := wh.service.Delete(r.Context(), WorkoutID(workoutID), principal.ID); err != nil {
		httpx.WriteStoreError(r.Context(), w, wh.logger, err, errorMapping, "Failed to delete workout")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
