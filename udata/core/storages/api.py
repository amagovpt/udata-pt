import os
from datetime import UTC, datetime
from uuid import uuid4

from dateutil.parser import parse as parse_date
from flask import current_app, json
from flask_storage.errors import FileExists, FileNotFound
from werkzeug.datastructures import FileStorage

from udata.api import api, fields

from . import chunks, utils
from .validation import validate_image_stream, validate_upload

META = "meta.json"

#: Marker file created in the chunk directory while a combine is running, so a
#: concurrent/replayed combine request for the same uuid fails cleanly instead
#: of racing the first one (reading chunks that are being deleted, or writing
#: the same target twice).
COMBINE_MARKER = "combining"

#: A marker older than this is considered stale (e.g. the worker died mid
#: combine) and a new combine may take over. Must comfortably exceed the
#: worst-case combine duration (read + write + hash of a max-size file).
COMBINE_MARKER_TTL = 15 * 60  # seconds

IMAGES_MIMETYPES = ("image/jpeg", "image/png", "image/webp")


uploaded_image_fields = api.model(
    "UploadedImage",
    {
        "success": fields.Boolean(
            description="Whether the upload succeeded or not.",
            readonly=True,
            default=True,
        ),
        "image": fields.ImageField(),
    },
)

chunk_status_fields = api.model(
    "UploadStatus",
    {"success": fields.Boolean, "error": fields.String, "code": fields.String},
)


image_parser = api.parser()
image_parser.add_argument("file", type=FileStorage, location="files")
image_parser.add_argument("bbox", type=str, location="form")


upload_parser = api.parser()
upload_parser.add_argument("file", type=FileStorage, location="files")
upload_parser.add_argument("uuid", type=str, location="form")
upload_parser.add_argument("filename", type=str, location="form")
upload_parser.add_argument("partindex", type=int, location="form")
upload_parser.add_argument("partbyteoffset", type=int, location="form")
upload_parser.add_argument("totalparts", type=int, location="form")
upload_parser.add_argument("chunksize", type=int, location="form")
# Optional (historical fineuploader field name): whole-file size in bytes, used
# to verify the reassembled file on combine. Legacy clients may not send it.
upload_parser.add_argument("totalfilesize", type=int, location="form")


class UploadStatus(Exception):
    def __init__(self, ok=True, error=None, code=None):
        super(UploadStatus, self).__init__()
        self.ok = ok
        self.error = error
        self.code = code


class UploadProgress(UploadStatus):
    """Raised on successful chunk uploaded"""

    pass


class UploadError(UploadStatus):
    """Raised on any upload error"""

    def __init__(self, error=None, code=None):
        super(UploadError, self).__init__(ok=False, error=error, code=code)


def on_upload_status(status):
    """Not an error, just raised when chunk is processed"""
    if status.ok:
        return {"success": True}, 200
    else:
        payload = {"success": False, "error": status.error}
        if status.code:
            payload["code"] = status.code
        return payload, 400


@api.errorhandler(UploadStatus)
@api.errorhandler(UploadError)
@api.errorhandler(UploadProgress)
@api.marshal_with(chunk_status_fields, code=200)
def api_upload_status(status):
    """API Upload response handler"""
    return on_upload_status(status)


def is_chunk_part():
    """Return True when the current request is an intermediate chunk part of a
    chunked upload (a part that carries file bytes), as opposed to the final
    combine request or a whole-file upload.

    Used as `exempt_when` on the upload rate-limiters: a chunked upload splits
    one logical upload into N small part-POSTs plus a final combine-POST, and
    only the combine (or a whole-file upload) actually creates the resource.
    Without this, a single large file would burst far past UPLOAD_LIMIT and get
    429'd mid-upload; exempting the cheap parts keeps the limit a per-upload
    abuse ceiling regardless of file size.
    """
    from flask import request

    try:
        totalparts = int(request.form.get("totalparts") or 0)
    except (TypeError, ValueError):
        totalparts = 0
    return totalparts > 1 and "file" in request.files


def chunk_filename(uuid, part):
    return os.path.join(str(uuid), str(part))


def get_file_size(file):
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    return size


def save_chunk(file, args):
    # Check file size
    if get_file_size(file) != args["chunksize"]:
        raise UploadProgress(ok=False, error="Chunk size mismatch", code="chunk-size-mismatch")
    filename = chunk_filename(args["uuid"], args["partindex"])
    # overwrite=True makes a client retry of the same part idempotent: after a
    # dropped connection the part may already be persisted, and re-sending it
    # must replace the previous bytes instead of failing with FileExists.
    chunks.save(file, filename=filename, overwrite=True)
    meta_filename = chunk_filename(args["uuid"], META)
    chunks.write(
        meta_filename,
        json.dumps(
            {
                "uuid": str(args["uuid"]),
                "filename": args["filename"],
                "totalparts": args["totalparts"],
                "totalfilesize": args["totalfilesize"],
                "lastchunk": datetime.now(UTC),
            }
        ),
        overwrite=True,
    )
    raise UploadProgress()


def _read_chunks_meta(uuid):
    """Read the chunk directory metadata, or None when absent/unreadable."""
    try:
        return json.loads(chunks.read(chunk_filename(uuid, META)))
    except (FileNotFound, FileNotFoundError, ValueError):
        return None


def _acquire_combine_marker(uuid):
    """Best-effort mutual exclusion between combines of the same upload.

    Creates ``<uuid>/combining`` holding the current timestamp. If the marker
    already exists with a fresh timestamp, another combine is running and this
    request backs off with a clean 400; a stale marker (crashed worker) is
    taken over. The check+write is not atomic (TOCTOU window), but the
    realistic race — a client retrying the combine seconds after a lost
    response — is fully covered, and the worst residual outcome with unique
    destination prefixes and atomic finalize is a duplicate file, never a
    corrupted one.
    """
    marker = chunk_filename(uuid, COMBINE_MARKER)
    now = datetime.now(UTC)
    try:
        chunks.write(marker, now.isoformat())
    except FileExists:
        try:
            started = parse_date(chunks.read(marker).decode())
            age = (now - started).total_seconds()
        except Exception:
            age = None
        if age is not None and age < COMBINE_MARKER_TTL:
            raise UploadError(
                "O ficheiro ainda está a ser processado. Aguarde uns instantes e "
                "verifique se o carregamento foi concluído antes de tentar novamente.",
                code="combine-in-progress",
            )
        chunks.write(marker, now.isoformat(), overwrite=True)


def _release_combine_marker(uuid):
    try:
        chunks.delete(chunk_filename(uuid, COMBINE_MARKER))
    except Exception:
        pass


def _delete_quietly(storage, filename):
    try:
        storage.delete(filename)
    except Exception:
        pass


def combine_chunks(storage, args, prefix=None):
    """
    Combine a chunked file into a whole file again.
    Goes through each part, in order,
    and appends that part's bytes to another destination file.
    Chunks are stored in the chunks storage.

    Hardened against the failure modes that used to corrupt files silently:
    - a replayed combine (client network retry) fails cleanly instead of racing
      the first one (in-progress marker + missing-chunks detection);
    - every part must exist before anything is written;
    - the reassembled size is verified against the client-provided
      ``totalfilesize`` when available;
    - on local storage the file is written under a temporary name and moved
      into place atomically, so readers never observe a half-written file.

    Aborts early (without leaving the partial file behind) if the reassembled
    size would exceed RESOURCES_FILE_MAX_SIZE, so an oversized upload never gets
    fully written to disk.
    """
    uuid = args["uuid"]
    totalparts = args["totalparts"]
    max_size = current_app.config.get("RESOURCES_FILE_MAX_SIZE")

    meta = _read_chunks_meta(uuid)
    if meta is None and not chunks.exists(chunk_filename(uuid, 0)):
        # Nothing left for this uuid: either nothing was uploaded or a previous
        # combine already succeeded and cleaned up (typical when the client
        # retries a combine whose response was lost in transit).
        raise UploadError(
            "Não existe nenhum carregamento em curso para este ficheiro. "
            "Pode já ter sido concluído — verifique antes de tentar novamente.",
            code="upload-not-found",
        )

    _acquire_combine_marker(uuid)

    # Normalize filename including extension
    target = utils.normalize(args["filename"])
    if prefix:
        target = os.path.join(prefix, target)

    # On local storage, write to a temporary name in the same directory (hence
    # the same filesystem) and rename into place at the end; other backends
    # (e.g. S3) already write objects atomically and keep the direct write.
    is_local = getattr(storage.backend, "root", None) is not None
    tmp_target = f"{target}.part-{uuid4().hex[:8]}" if is_local else target

    try:
        missing = [i for i in range(totalparts) if not chunks.exists(chunk_filename(uuid, i))]
        if missing:
            raise UploadError(_chunks_missing_error(), code="chunks-missing")

        expected_size = args["totalfilesize"]
        if expected_size is None and meta:
            expected_size = meta.get("totalfilesize")

        written = 0
        too_large = False
        try:
            with storage.open(tmp_target, "wb") as out:
                for i in range(totalparts):
                    data = chunks.read(chunk_filename(uuid, i))
                    written += len(data)
                    if max_size and written > max_size:
                        too_large = True
                        break
                    out.write(data)
        except (FileNotFound, FileNotFoundError):
            # A concurrent combine (or the retention purge) deleted the chunks
            # while this one was reading them.
            _delete_quietly(storage, tmp_target)
            raise UploadError(_chunks_missing_error(), code="chunks-missing")

        if too_large:
            _delete_quietly(storage, tmp_target)
            _purge_chunks(uuid, totalparts)
            raise UploadError(_max_size_error(max_size), code="file-too-large")

        if expected_size is not None and written != expected_size:
            # Deterministic failure: some part holds the wrong bytes, so
            # retrying the combine can never succeed. Purge everything so the
            # client restarts the upload with a fresh uuid.
            _delete_quietly(storage, tmp_target)
            _purge_chunks(uuid, totalparts)
            raise UploadError(
                "O ficheiro carregado está incompleto ou foi alterado durante o envio "
                f"(esperados {expected_size} bytes, recebidos {written}). "
                "Tente enviar o ficheiro novamente.",
                code="size-mismatch",
            )

        if tmp_target != target:
            storage.backend.move(tmp_target, target)
    except Exception:
        # Leave no in-progress marker behind so a later retry can proceed
        # (paths that purged the whole chunk directory make this a no-op).
        _release_combine_marker(uuid)
        raise

    _purge_chunks(uuid, totalparts)
    return target


def _purge_chunks(uuid, totalparts):
    """Best-effort removal of any leftover chunk parts, markers and metadata."""
    for i in range(totalparts):
        try:
            chunks.delete(chunk_filename(uuid, i))
        except Exception:
            pass
    for name in (META, COMBINE_MARKER):
        try:
            chunks.delete(chunk_filename(uuid, name))
        except Exception:
            pass
    try:
        # Also drop the (now empty) chunk directory on backends that have one.
        chunks.delete(str(uuid))
    except Exception:
        pass


def _max_size_error(max_size):
    return f"O ficheiro excede o tamanho máximo permitido de {max_size // (1024 * 1024)} MB."


def _chunks_missing_error():
    return "Faltam partes do ficheiro carregado. Tente enviar o ficheiro novamente."


def handle_upload(storage, prefix=None):
    args = upload_parser.parse_args()
    is_chunk = args["totalparts"] and args["totalparts"] > 1
    uploaded_file = args["file"]

    if is_chunk:
        if uploaded_file:
            save_chunk(uploaded_file, args)
        else:
            fs_filename = combine_chunks(storage, args, prefix=prefix)
    elif not uploaded_file:
        raise UploadError("Missing file parameter")
    else:
        # Normalize filename including extension
        filename = utils.normalize(uploaded_file.filename)
        fs_filename = storage.save(uploaded_file, prefix=prefix, filename=filename, overwrite=True)

    metadata = storage.metadata(fs_filename)

    # Enforce the maximum resource file size server-side (the client-side guard
    # is bypassable). The chunked path is already capped in combine_chunks; this
    # also covers single-shot uploads.
    max_size = current_app.config.get("RESOURCES_FILE_MAX_SIZE")
    if max_size and metadata.get("size", 0) > max_size:
        storage.delete(fs_filename)
        api.abort(413, _max_size_error(max_size))

    metadata["last_modified_internal"] = metadata.pop("modified")
    metadata["fs_filename"] = fs_filename
    checksum = metadata.pop("checksum")
    algo, checksum = checksum.split(":", 1)
    metadata[algo] = checksum
    metadata["format"] = utils.extension(fs_filename)

    # Validate extension against the allowed list
    ext = metadata["format"].lower()
    allowed = [e.lower() for e in current_app.config.get("ALLOWED_RESOURCES_EXTENSIONS", [])]
    if ext and ext not in allowed:
        storage.delete(fs_filename)
        api.abort(415, f"A extensão de ficheiro '.{ext}' não é permitida.")

    # Validate file content against malicious payloads
    filepath = storage.path(fs_filename)
    error = validate_upload(filepath, metadata.get("mime", ""), metadata.get("format", ""))
    if error:
        api.abort(415, error)

    return metadata


def parse_uploaded_image(field):
    """Parse an uploaded image and save into a ImageField()"""
    args = image_parser.parse_args()

    image = args["file"]
    if image.mimetype not in IMAGES_MIMETYPES:
        api.abort(400, "Formato de imagem não suportado")

    # Validate file content: magic bytes, Pillow parsing, script scanning
    error = validate_image_stream(image)
    if error:
        api.abort(415, error)

    bbox = args.get("bbox", None)
    if bbox:
        bbox = [int(float(c)) for c in bbox.split(",")]
    field.save(image, bbox=bbox)
