from datetime import datetime, timedelta, timezone


class TimeUtils:
    """
    Fonctions de conversion des timestamps utilisés
    dans les différents artefacts Windows.
    """

    WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
    UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

    @staticmethod
    def chrome_time_to_datetime(value):

        try:

            if not value:
                return None

            return TimeUtils.WINDOWS_EPOCH + timedelta(microseconds=value)

        except Exception:

            return None

    @staticmethod
    def filetime_to_datetime(value):

        try:

            if not value:
                return None

            return TimeUtils.WINDOWS_EPOCH + timedelta(
                microseconds=value / 10
            )

        except Exception:

            return None

    @staticmethod
    def unix_to_datetime(value):

        try:

            if value is None:
                return None

            return datetime.fromtimestamp(value, tz=timezone.utc)

        except Exception:

            return None

    @staticmethod
    def coerce_timestamp(value):
        """Coerce a raw event/parser timestamp into a naive UTC datetime.

        Named "coerce" rather than "normalize" deliberately: this doesn't
        just adjust an already-datetime value, it accepts several different
        input representations (string, aware datetime, naive datetime) and
        forces them all into one canonical type and form.

        Returns None if `value` is missing or cannot be coerced. Never
        raises and never logs — the caller decides how a rejected
        timestamp should be counted or reported.

        This is the single source of truth for "canonical UTC timestamp"
        across the whole pipeline: modules.normalizer.event (event_id
        hashing) and modules.timeline.timestamps (the timeline stage) both
        delegate here instead of keeping their own copies.
        """

        if value is None:
            return None

        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return None

        if not isinstance(value, datetime):
            return None

        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)

        return value