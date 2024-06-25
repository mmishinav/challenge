from rest_framework import response, decorators as rest_decorators, permissions as rest_permissions

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


@swagger_auto_schema(
    method="POST",
    operation_summary="Pay for a subscription",
    operation_description="Processes the payment for a subscription.",
    responses={
        200: openapi.Response(
            description="Payment processed successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "msg": openapi.Schema(type=openapi.TYPE_STRING, example="Success"),
                },
            ),
        ),
        401: openapi.Response(
            description="Unauthorized",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "detail": openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Authentication credentials were not provided or are invalid",
                    ),
                },
            ),
        ),
        403: openapi.Response(
            description="Permission denied",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "detail": openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Forbidden",
                        description="Error message indicating insufficient permissions."
                    )
                }
            )
        ),
    },
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    return response.Response({"msg": "Success"}, 200)


@swagger_auto_schema(
    method="POST",
    operation_summary="Retrieve subscriptions",
    operation_description="Retrieves the list of all subscriptions for the user.",
    responses={
        200: openapi.Response(
            description="Success",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "msg": openapi.Schema(type=openapi.TYPE_STRING, example="Success"),
                },
            ),
        ),
        401: openapi.Response(
            description="Unauthorized",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "detail": openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Authentication credentials were not provided or are invalid",
                        description="Error message indicating missing or invalid authentication credentials."
                    )
                }
            )
        ),
        403: openapi.Response(
            description="Permission denied",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "detail": openapi.Schema(
                        type=openapi.TYPE_STRING,
                        example="Forbidden",
                        description="Error message indicating insufficient permissions."
                    )
                }
            )
        ),
    },
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    return response.Response({"msg": "Success"}, 200)
