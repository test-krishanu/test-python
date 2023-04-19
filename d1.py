from django.db.models import Count, Prefetch, Q
from django_filters.rest_framework import DjangoFilterBackend, FilterSet
from drf_spectacular.utils import extend_schema
from knowl_api.core.authentication import UserAPIKeyAuthentication
from knowl_api.core.code_integrations.github import (
    GithubAuthorizationError,
    GithubIntegration,
)
from knowl_api.core.models import (
    Company,
    Document,
    DocumentBranch,
    DocumentComment,
    DocumentContributor,
    DocumentGitNode,
    DocumentGitNodeAction,
    DocumentImage,
    PRDocWorkflow,
    PRNoUpdateReason,
)
from knowl_api.core.permissions import IsDocumentAuthenticated
from knowl_api.core.serializers import (
    CommentSerializer,
    CompanySerializer,
    DocumentBranchDetailSerializer,
    DocumentChildrenSerializer,
    DocumentContributorSerializer,
    DocumentGitNodeActionInputSerializer,
    DocumentGitNodeActionSerializer,
    DocumentGitNodeCopySerializer,
    DocumentGitNodeSearchOutputSerializer,
    DocumentGitNodeSearchSerializer,
    DocumentGitNodeSerializer,
    DocumentImageSerializer,
    DocumentSerializer,
    DocumentSerializerWithAncestors,
    GenerateGithubTokenSerializer,
    ImageFilePathSerializer,
    PRDocWorkflowSerializer,
    PRNoUpdateReasonSerializer,
    UserTokenObtainPairSerializer,
)
from rest_framework import filters, mixins, pagination, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework_extensions.mixins import NestedViewSetMixin
from rest_framework_simplejwt.views import TokenObtainPairView


class CompanyViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Provide Company information"""

    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return super().get_queryset().filter(id=self.request.user.company_id)


class UserObtainTokenPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = UserTokenObtainPairSerializer


class DocumentViewSet(viewsets.ModelViewSet):
    """Provide Document Information"""

    serializer_class = DocumentSerializer
    permission_classes = (IsAuthenticated,)
    filter_backends = [filters.SearchFilter]
    search_fields = ["name"]

    def get_queryset(self):
        user = self.request.user
        queryset = Document.objects.filter_by_company(user.company).select_related("created_by")
        if self.action in ["recent", "search"]:
            queryset = queryset.exclude(doc_type=Document.DOC_TYPES.branch)
        if self.action == "list":
            return queryset.filter(parent__isnull=True, doc_type=Document.DOC_TYPES.project).order_by("created")
        return queryset

    def get_serializer_class(self):
        if self.action == "retrieve":
            return DocumentSerializerWithAncestors
        return self.serializer_class

    @extend_schema(responses=DocumentChildrenSerializer(many=True))
    @action(detail=True, methods=["get"])
    def children(self, request, pk=None):
        document = self.get_object()
        serializer = DocumentChildrenSerializer(
            document.children.exclude(doc_type=Document.DOC_TYPES.branch)
            .select_related("created_by")
            .annotate(contributor_count=Count("documentcontributor"))
            .order_by("-modified"),
            many=True,
        )
        return Response(serializer.data)

    @extend_schema(responses=DocumentBranchDetailSerializer(many=True))
    @action(detail=True, methods=["get"])
    def branches(self, request, pk=None):
        document = self.get_object()
        serializer = DocumentBranchDetailSerializer(
            DocumentBranch.objects.filter(document__parent=document, document__doc_type=Document.DOC_TYPES.branch)
            .select_related("document", "document__created_by")
            .order_by("-created"),
            many=True,
        )
        return Response(serializer.data)

    @action(detail=False, methods=["get"])
    def recent(self, request):
        queryset = self.get_queryset().order_by("-modified")[:10]
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @extend_schema(request=DocumentGitNodeSearchSerializer, responses=DocumentGitNodeSearchOutputSerializer(many=True))
    @action(
        detail=False,
        methods=["post"],
        authentication_classes=api_settings.DEFAULT_AUTHENTICATION_CLASSES + [UserAPIKeyAuthentication],
    )
    def search_git_nodes(self, request):
        # TODO: try to make it work with GET (right now it is difficult due to complex input)
        input_serializer = DocumentGitNodeSearchSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        # TODO: optimize the query by using lines in query itself (ANY(affected_lines) between start_line and end_line)
        qs = DocumentGitNode.objects.filter(
            document__company=request.user.company, document__is_archived=False
        ).select_related("document", "last_updated_by")
        data = input_serializer.validated_data
        if not data:
            qs = qs.none()
        else:
            qs = qs.filter(owner=data["owner"], repo=data["repo"], path__in=data["paths"])
        if data.get("code_branch"):
            # filter by code branch provided in input but also keep main docs
            qs = qs.filter(
                Q(document__documentbranch__isnull=True)
                | (
                    Q(
                        document__documentbranch__git_owner=data["owner"],
                        document__documentbranch__git_repo=data["repo"],
                        document__documentbranch__git_branch=data["code_branch"],
                    )
                )
            )
        return Response(DocumentGitNodeSearchOutputSerializer(qs, many=True).data)

    @extend_schema(request=DocumentGitNodeActionInputSerializer, responses=DocumentGitNodeActionSerializer(many=True))
    @action(detail=False, methods=["post"])
    def git_node_actions(self, request):
        input_serializer = DocumentGitNodeActionInputSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        data = input_serializer.validated_data
        git_node_actions = data["user_actions"]
        output_git_node_actions = []
        for git_node_action in git_node_actions:
            git_node = git_node_action["document_git_node"]
            if git_node.document.company != request.user.company:
                # git node document doesn't belong to user's company
                continue
            git_node_action["commit_sha"] = data["commit_sha"]
            user_input = git_node_action.pop("user_input")
            obj, _ = DocumentGitNodeAction.objects.update_or_create(
                **git_node_action, defaults=dict(user_input=user_input, created_by=request.user)
            )
            output_git_node_actions.append(obj)
        return Response(DocumentGitNodeActionSerializer(output_git_node_actions, many=True).data)

    @action(detail=False, methods=["get"])
    def search(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)


class UserViewSet(viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    @extend_schema(request=GenerateGithubTokenSerializer)
    @action(detail=False, methods=["post"], url_path="generate-github-token")
    def generate_github_token(self, request):
        user = request.user
        serializer = GenerateGithubTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            access_token = GithubIntegration.generate_access_token(serializer.validated_data["code"])
        except GithubAuthorizationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        user.github_token = access_token
        user.save()
        return Response({"access_token": access_token})


class ImageViewSet(viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    @extend_schema(request=ImageFilePathSerializer)
    @action(detail=False, methods=["post"], url_path="generate-presigned-url")
    def generate_presigned_url(self, request):
        serializer = ImageFilePathSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        signed_url = serializer.validated_data["file_path"]
        return Response({"signed_url": signed_url})


class NestedViewSetCreateMixin(NestedViewSetMixin):
    def perform_create(self, serializer):
        kwargs_id = {key + "_id": value for key, value in self.get_parents_query_dict().items()}
        serializer.save(**kwargs_id)


class DocumentNestedViewSetCreateMixin(NestedViewSetCreateMixin):
    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .filter(document__company_id=self.request.user.company_id, document__is_archived=False)
        )


class DocumentGitNodeViewSet(DocumentNestedViewSetCreateMixin, viewsets.ModelViewSet):
    """CRUD Document Git Nodes"""

    queryset = DocumentGitNode.objects.all()
    serializer_class = DocumentGitNodeSerializer
    permission_classes = (IsDocumentAuthenticated,)

    @extend_schema(request=DocumentGitNodeCopySerializer)
    @action(detail=True, methods=["post"])
    def copy(self, request, parent_lookup_document=None, pk=None):
        instance = self.get_object()
        serializer = DocumentGitNodeCopySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # TODO: verify if copied instance document has permission.
        copied_instance = instance.copy(serializer.validated_data["destination_document"])
        return Response(DocumentGitNodeSerializer(copied_instance).data)


class DocumentImageViewSet(NestedViewSetCreateMixin, viewsets.ModelViewSet):
    """CRUD Document Images"""

    queryset = DocumentImage.objects.all()
    serializer_class = DocumentImageSerializer
    permission_classes = (IsDocumentAuthenticated,)


class DocumentContributorViewSet(NestedViewSetMixin, viewsets.ReadOnlyModelViewSet):
    """Read Document Contributors"""

    queryset = DocumentContributor.objects.all()
    serializer_class = DocumentContributorSerializer
    permission_classes = (IsDocumentAuthenticated,)

    def get_queryset(self):
        return super().get_queryset().select_related("user")


class CommentsPagination(pagination.PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 50
    page_query_param = "p"


class CommentViewSet(DocumentNestedViewSetCreateMixin, viewsets.ModelViewSet):
    permission_classes = (IsDocumentAuthenticated,)
    queryset = DocumentComment.objects.all()
    serializer_class = CommentSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["status"]
    pagination_class = CommentsPagination

    def get_queryset(self):
        qs = super().get_queryset()
        if self.action == "list":
            qs = qs.filter(parent__isnull=True)
        else:
            # update/delete only allowed by creator
            qs = qs.filter(created_by=self.request.user)
        qs = qs.select_related("created_by").prefetch_related(
            Prefetch("replies", queryset=DocumentComment.objects.all().select_related("created_by")),
            "attachments",
        )
        return qs

    # TODO: need clarification
    # @action(detail=False, methods=["get"])
    # def reply_count(self, request, parent_lookup_document=None):
    #     status_counts = self.get_queryset().values("status").annotate(count=Count("status"))
    #     result = {status_dict["status"]: status_dict["count"] for status_dict in status_counts}
    #     return Response(result)


class PRNoUpdateReasonViewSet(viewsets.ModelViewSet):
    """
    CRUD PR no update reason
    TODO: Think of a way to make it more secure (may be we can filter by company of last updated by)
    """

    queryset = PRNoUpdateReason.objects.all().select_related("last_updated_by")
    serializer_class = PRNoUpdateReasonSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return super().get_queryset().filter(company_id=self.request.user.company_id)


class PRDocWorkflowFilter(FilterSet):
    class Meta:
        model = PRDocWorkflow
        fields = ["owner", "repo", "pr_no"]

    def filter_queryset(self, queryset):
        # making sure all fields are required.
        if not all(self.form.cleaned_data.values()):
            return queryset.none()
        return super().filter_queryset(queryset)


class PRDocWorkflowViewSet(viewsets.GenericViewSet, mixins.ListModelMixin, mixins.CreateModelMixin):
    """
    CRUD PR no update reason
    TODO: Think of a way to make it more secure (may be we can filter by company of last updated by)
    """

    queryset = PRDocWorkflow.objects.all().select_related("last_updated_by")
    serializer_class = PRDocWorkflowSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES + [UserAPIKeyAuthentication]
    filter_backends = (DjangoFilterBackend,)
    filterset_class = PRDocWorkflowFilter

    def get_queryset(self):
        return super().get_queryset().filter(company_id=self.request.user.company_id)
