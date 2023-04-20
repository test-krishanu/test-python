import logging

from django.db.models import Count, Prefetch, Q
from django_filters.rest_framework import DjangoFilterBackend, FilterSet
from drf_spectacular.utils import extend_schema
from knowl_api.core import utils
from knowl_api.core.authentication import UserAPIKeyAuthentication
from knowl_api.core.code_integrations import (
    GitAuthorizationError,
    git_platform_registry,
)
from knowl_api.core.models import (
    AutomatedDocMetadata,
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
    UserAPIKey,
    UserCoachMarkProgress,
)
from knowl_api.core.permissions import IsDocumentAuthenticated
from knowl_api.core.serializers import (
    AutomatedDocMetadataSerializer,
    CodeExplanationSerializer,
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
    DocumentImageCopySerializer,
    DocumentImageSerializer,
    DocumentSerializer,
    DocumentSerializerWithAncestors,
    GenerateGitTokenSerializer,
    ImageFilePathSerializer,
    PRDocWorkflowSerializer,
    PRNoUpdateReasonSerializer,
    RefreshGitTokenSerializer,
    SocialLoginInputSerializer,
    UserAPIKeySerializer,
    UserCoachMarkProgressSerializer,
    UserTokenObtainPairSerializer,
    ValidateInviteSerializer,
)
from knowl_api.core.utils import code_text_to_doc_html
from knowl_api.core.yjs_api import YjsApi
from rest_framework import filters, mixins, pagination, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework_extensions.mixins import NestedViewSetMixin
from rest_framework_simplejwt.views import TokenObtainPairView

logger = logging.getLogger(__name__)


class CompanyViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Provide Company information"""

    queryset = Company.objects.all()
    serializer_class = CompanySerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return super().get_queryset().filter(id=self.request.user.company_id)

    @extend_schema(request=ValidateInviteSerializer)
    @action(detail=False, methods=["post"], permission_classes=(AllowAny,))
    def validate_invite(self, request):
        input_serializer = ValidateInviteSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        company = input_serializer.validated_data["company"]
        return Response({"name": company.name})


class UserObtainTokenPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = UserTokenObtainPairSerializer


class SocialLoginView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = SocialLoginInputSerializer


class DocumentViewSet(viewsets.ModelViewSet):
    """Provide Document Information"""

    serializer_class = DocumentSerializer
    permission_classes = (IsAuthenticated,)
    filter_backends = [filters.SearchFilter]
    search_fields = ["name"]

    def get_queryset(self):
        user = self.request.user
        queryset = Document.objects.filter_by_user(user).select_related("created_by")
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
        qs = (
            DocumentGitNode.objects.filter_by_user(request.user)
            .filter(document__is_archived=False)
            .select_related("document", "last_updated_by")
        )
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

    @extend_schema(request=CodeExplanationSerializer)
    @action(detail=True, methods=["post"], url_path="generate-code-explanation")
    def generate_code_explanation(self, request, *args, **kwargs):
        # TODO: add user/document level rate limit to avoid misuse
        serializer = CodeExplanationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        html_output = code_text_to_doc_html(serializer.validated_data["code_text"])
        return Response({"doc_html": html_output})

    @action(detail=True, methods=["post"], url_path="pr-branch")
    def pr_branch(self, request, **kwargs):
        document = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if document.doc_type == Document.DOC_TYPES.branch:
            return Response({"id": document.id})
        branch_data = serializer.validated_data["branch"]
        document_branches = (
            DocumentBranch.objects.select_related("document")
            .filter(
                document__parent=document,
                document__doc_type=Document.DOC_TYPES.branch,
                branch_status=DocumentBranch.BRANCH_STATUS.created,
                git_owner=branch_data["git_owner"],
                git_repo=branch_data["git_repo"],
                git_branch=branch_data["git_branch"],
            )
            .prefetch_related("document")
        )
        document_branch = document_branches.first()
        if document_branch:
            branch = document_branch.document
        else:
            data = {
                "name": branch_data["git_branch"],
                "branch": {
                    "branch_name": branch_data["git_branch"],
                    "git_owner": branch_data["git_owner"],
                    "git_repo": branch_data["git_repo"],
                    "git_branch": branch_data["git_branch"],
                },
            }
            yjsapi = YjsApi(token=request.auth.token.decode())
            response = yjsapi.create_branch(document_id=document.id, data=data)
            branch_id = response.json()["id"]
            branch = Document.objects.get(id=branch_id)
        new_git_nodes = serializer.validated_data.get("new_git_nodes", [])
        update_git_nodes = serializer.validated_data.get("update_git_nodes", [])
        if update_git_nodes:
            not_found = DocumentGitNode.update_live_code(update_git_nodes, branch)
            new_git_nodes.extend(not_found)
        if new_git_nodes:
            utils.update_doc_content(branch, request.auth.token, ai_prompt=None, new_git_nodes=new_git_nodes)
        return Response({"id": branch.id})


class UserViewSet(viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    @extend_schema(request=GenerateGitTokenSerializer)
    @action(detail=False, methods=["post"], url_path="generate-git-token")
    def generate_git_token(self, request):
        user = request.user
        serializer = GenerateGitTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        git_platform = git_platform_registry[user.company.git_platform]
        try:
            access_token_dict = git_platform.generate_access_token(
                validated_data["code"], validated_data["redirect_uri"]
            )
        except GitAuthorizationError as e:
            logger.error("Error in getting access token: %s", str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        access_token = access_token_dict["access_token"]
        refresh_token = access_token_dict.get("refresh_token")
        user.github_token = access_token
        user.save()
        return Response({"access_token": access_token, "refresh_token": refresh_token})

    @extend_schema(request=RefreshGitTokenSerializer)
    @action(detail=False, methods=["post"], url_path="refresh-git-token")
    def refresh_git_token(self, request):
        user = request.user
        serializer = RefreshGitTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        git_platform = git_platform_registry[user.company.git_platform]
        try:
            access_token_dict = git_platform.get_token_from_refresh_token(serializer.validated_data["refresh_token"])
        except GitAuthorizationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        access_token = access_token_dict["access_token"]
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
            .filter(Q(document__user__isnull=True) | Q(document__user_id=self.request.user.id))
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
        destination_doc = serializer.validated_data["destination_document"]
        # TODO: verify if copied instance document has permission.
        copied_instance = instance.copy(destination_doc)
        return Response(DocumentGitNodeSerializer(copied_instance).data)


class DocumentImageViewSet(NestedViewSetCreateMixin, viewsets.ModelViewSet):
    """CRUD Document Images"""

    queryset = DocumentImage.objects.all()
    serializer_class = DocumentImageSerializer
    permission_classes = (IsDocumentAuthenticated,)

    @extend_schema(request=DocumentImageCopySerializer)
    @action(detail=True, methods=["post"])
    def copy(self, request, parent_lookup_document=None, pk=None):
        instance = self.get_object()
        serializer = DocumentImageCopySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        destination_doc = serializer.validated_data["destination_document"]
        # TODO: verify if copied instance document has permission.
        copied_instance = instance.copy(destination_doc)
        return Response(DocumentImageSerializer(copied_instance).data)


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


class RequiredFilterSetMixin(FilterSet):
    def filter_queryset(self, queryset):
        # making sure all fields are required.
        if not all(self.form.cleaned_data.values()):
            return queryset.none()
        return super().filter_queryset(queryset)


class PRNoUpdateReasonFilter(RequiredFilterSetMixin):
    class Meta:
        model = PRNoUpdateReason
        fields = ["owner", "repo", "pr_no"]


class PRDocWorkflowFilter(RequiredFilterSetMixin):
    class Meta:
        model = PRDocWorkflow
        fields = ["owner", "repo", "pr_no"]


class AutomatedDocMetadataFilter(RequiredFilterSetMixin):
    class Meta:
        model = AutomatedDocMetadata
        fields = ["owner", "repo"]


class PRNoUpdateReasonViewSet(viewsets.ModelViewSet):
    """
    CRUD PR no update reason
    """

    queryset = PRNoUpdateReason.objects.all().select_related("last_updated_by")
    serializer_class = PRNoUpdateReasonSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES + [UserAPIKeyAuthentication]
    filter_backends = (DjangoFilterBackend,)
    filterset_class = PRNoUpdateReasonFilter

    def get_queryset(self):
        return super().get_queryset().filter(company_id=self.request.user.company_id).order_by("-modified")


class PRDocWorkflowViewSet(viewsets.GenericViewSet, mixins.ListModelMixin, mixins.CreateModelMixin):
    """
    CRUD PR doc workflow run viewset - to store workflow run id of each PR to be used in PR diff page.
    """

    queryset = PRDocWorkflow.objects.all().select_related("last_updated_by")
    serializer_class = PRDocWorkflowSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES + [UserAPIKeyAuthentication]
    filter_backends = (DjangoFilterBackend,)
    filterset_class = PRDocWorkflowFilter

    def get_queryset(self):
        return super().get_queryset().filter(company_id=self.request.user.company_id)


class AutomatedDocMetadataViewSet(viewsets.ModelViewSet):
    """
    CRUD automated doc metadata viewset - to store metadata and doc and code (file) mapping
    """

    queryset = AutomatedDocMetadata.objects.all().select_related("last_updated_by")
    serializer_class = AutomatedDocMetadataSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES + [UserAPIKeyAuthentication]
    filter_backends = (DjangoFilterBackend,)
    filterset_class = AutomatedDocMetadataFilter

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .filter_by_user(self.request.user)
            .filter(document__is_archived=False)
            .select_related("document")
        )


class UserAPIKeyViewSet(viewsets.ModelViewSet):
    """
    CRUD User Api Key viewset - to view, generate api key
    """

    queryset = UserAPIKey.objects.all().order_by("-created")
    serializer_class = UserAPIKeySerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return super().get_queryset().filter(user=self.request.user)


class UserCoachMarkProgressViewSet(viewsets.ModelViewSet):
    """
    CRUD User Coach Mark progress viewset - to maintain coach mark progress at user and story level
    """

    queryset = UserCoachMarkProgress.objects.all().order_by("-created")
    serializer_class = UserCoachMarkProgressSerializer
    permission_classes = (IsAuthenticated,)
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ("story",)

    def get_queryset(self):
        return super().get_queryset().filter(user=self.request.user)