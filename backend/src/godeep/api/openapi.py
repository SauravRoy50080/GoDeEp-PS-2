"""Document streaming runtime uploads without pre-reading their bounded body."""

from godeep.schemas.runtime_captures import RuntimeTrace


def document_runtime_upload(application):
    original = application.openapi

    def openapi():
        document = original()
        schema = RuntimeTrace.model_json_schema(
            ref_template="#/components/schemas/RuntimeTrace_{model}"
        )
        definitions = schema.pop("$defs", {})
        models = document.setdefault("components", {}).setdefault("schemas", {})
        models["RuntimeTrace"] = schema
        models.update({"RuntimeTrace_" + name: value for name, value in definitions.items()})
        return document

    application.openapi = openapi
