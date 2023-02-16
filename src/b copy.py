import uuid

from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models
from model_utils import Choices
from model_utils.models import TimeStampedModel
from rest_framework_api_key.models import AbstractAPIKey, BaseAPIKeyManager
from simple_history.models import HistoricalRecords
from tree_queries.models import TreeNode
from tree_queries.query import TreeQuerySet


class UUIDAbstractModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class Company(TimeStampedModel):
    name = models.CharField(max_length=512)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "companies"


class KnowlUserManager(UserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        company = Company.objects.create(
            name=f"Company {uuid.uuid4()}",
        )
        extra_fields.update({"company": company})

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, password, **extra_fields)


class User(AbstractUser, UUIDAbstractModel):
    username = None

    email = models.EmailField(max_length=254, unique=True)
    first_name = models.CharField(max_length=256)
    last_name = models.CharField(max_length=256)
    can_login = models.BooleanField(default=False)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    github_token = models.CharField(max_length=128, null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = KnowlUserManager()

    def __str__(self):
        return self.email


class DocumentQueryset(TreeQuerySet):
    """Define a model manager for Documents"""

    def filter_by_company(self, company):
        return self.filter(company=company)


class DocumentMananger(models.Manager):
    def get_queryset(self):
        return DocumentQueryset(self.model, using=self._db).filter(is_archived=False)


class Document(TimeStampedModel, UUIDAbstractModel, TreeNode):
    DOC_TYPES = Choices((1, "doc", "document"), (2, "project", "project"), (3, "branch", "branch"))

    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    name = models.CharField(max_length=128)
    is_archived = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    doc_type = models.PositiveSmallIntegerField(choices=DOC_TYPES, db_index=True)

    objects = DocumentMananger.from_queryset(DocumentQueryset)()
    all_objects = DocumentQueryset.as_manager()
    tree_objects = DocumentQueryset.as_manager(with_tree_fields=True)

    def __str__(self):
        return self.name

    def delete(self, using=None, keep_parents=False):
        for child in self.descendants():
            child.is_archived = True
            child.save()
        self.is_archived = True
        self.save()


class DocumentBranch(TimeStampedModel):
    BRANCH_STATUS = Choices((1, "created", "created"), (2, "merged", "merged"), (3, "deleted", "deleted"))

    document = models.OneToOneField(Document, on_delete=models.CASCADE, primary_key=True)
    # branch fields
    branch_name = models.CharField(max_length=256)
    branch_status = models.PositiveSmallIntegerField(choices=BRANCH_STATUS, default=BRANCH_STATUS.created)
    # if branch is hooked to any git repo branch
    git_owner = models.CharField(max_length=256, null=True, blank=True)
    git_repo = models.CharField(max_length=256, null=True, blank=True)
    git_branch = models.CharField(max_length=256, null=True, blank=True)
    git_pr_no = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return self.branch_name

    @property
    def status(self):
        return DocumentBranch.BRANCH_STATUS.deleted if self.document.is_archived else self.branch_status


class DocumentGitNode(TimeStampedModel, UUIDAbstractModel):
    NODE_STATUS = Choices((1, "in_sync", "In Sync"), (2, "doc_ahead", "Document Ahead"))

    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    owner = models.CharField(max_length=512)
    repo = models.CharField(max_length=512)
    path = models.CharField(max_length=512)
    branch = models.CharField(max_length=512)
    commit_sha = models.CharField(max_length=64)
    start_line = models.PositiveIntegerField()
    end_line = models.PositiveIntegerField()
    mark_id = models.CharField(max_length=512, null=True, blank=True, help_text="Mark id from lexical selected text")
    status = models.PositiveSmallIntegerField(choices=NODE_STATUS, default=NODE_STATUS.in_sync)
    last_updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        help_text="Parent node in main doc. will be used when merge branch",
    )

    history = HistoricalRecords()

    def copy(self, new_doc: Document):
        parent_id = self.id
        self.pk = None
        self.document = new_doc
        if new_doc.doc_type == Document.DOC_TYPES.branch:
            self.parent_id = parent_id
        self.save()
        return self


class DocumentGitNodeAction(TimeStampedModel, UUIDAbstractModel):
    USER_INPUTS = Choices(
        (1, "updated", "Snippet Updated"),
        (2, "not_required", "Update not required"),
        (3, "reviewed", "Update reviewed"),
        (4, "not_reviewed", "Update not reviewed"),
        (5, "update_later", "Update later"),
        (6, "no_action", "No action taken"),
    )

    document_git_node = models.ForeignKey(DocumentGitNode, on_delete=models.CASCADE)
    commit_sha = models.CharField(max_length=64, help_text="commit id when this update made")
    user_input = models.PositiveSmallIntegerField(choices=USER_INPUTS, default=USER_INPUTS.no_action)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)


def document_image_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/<company_id>/document_<id>/<uuid>/<filename>
    # to sort all documents of a company in one path
    return "{0}/document_{1}/images/{2}/{3}".format(
        instance.document.company_id, instance.document.id, uuid.uuid4(), filename
    )


class DocumentImage(TimeStampedModel, UUIDAbstractModel):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    image = models.FileField(max_length=1024, upload_to=document_image_path, null=True, blank=True)
    image_url = models.URLField(max_length=1024, null=True, blank=True)

    history = HistoricalRecords()


class DocumentContributor(TimeStampedModel, UUIDAbstractModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    document = models.ForeignKey(Document, on_delete=models.CASCADE)


def comment_attachment_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/<company_id>/document_<id>/comment_<id>/<uuid>/<filename>
    # to sort all documents of a company in one path
    return "{0}/document_{1}/comments_attachments/comment_{2}/{3}/{4}".format(
        instance.comment.document.company_id, instance.comment.document.id, instance.comment.id, uuid.uuid4(), filename
    )


class DocumentComment(TimeStampedModel, UUIDAbstractModel):
    STATUS_TYPES = Choices((2, "resolved", "resolved"), (1, "open", "open"))
    # content fields
    message = models.TextField(blank=True)

    # meta fields
    parent = models.ForeignKey("self", on_delete=models.CASCADE, null=True, related_name="replies")
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    # the following fields only make sense for parent comments. The replies will have the following values as null.
    # use choices api
    status = models.IntegerField(choices=STATUS_TYPES, default=STATUS_TYPES.open)

    class Meta:
        ordering = ["modified"]
        index_together = ["document", "modified"]


class DocumentCommentAttachment(TimeStampedModel, UUIDAbstractModel):
    comment = models.ForeignKey(DocumentComment, on_delete=models.CASCADE, related_name="attachments")
    attachment = models.FileField(upload_to=comment_attachment_path, max_length=2048, null=True, blank=True)


class DocumentHistory(TimeStampedModel, UUIDAbstractModel):
    EVENT_TYPES = Choices(
        (1, "recurring_diff", "Recurring Diff"),
        (2, "session_close", "Closed Session"),
    )

    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    doc_state = models.BinaryField(blank=True)
    event_type = models.PositiveSmallIntegerField(choices=EVENT_TYPES)
    contributors = models.ManyToManyField(User, blank=True)

    class Meta:
        index_together = (("document", "created"),)


class UserAPIKeyManager(BaseAPIKeyManager):
    def get_usable_keys(self) -> models.QuerySet:
        return super().get_usable_keys().filter(user__is_active=True)


class UserAPIKey(AbstractAPIKey):
    objects = UserAPIKeyManager()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_keys")

    class Meta(AbstractAPIKey.Meta):
        verbose_name = "User API key"
        verbose_name_plural = "User API keys"


class PRNoUpdateReason(TimeStampedModel, UUIDAbstractModel):
    owner = models.CharField(max_length=512)
    repo = models.CharField(max_length=512)
    pr_no = models.PositiveIntegerField()
    file_path = models.CharField(max_length=512, null=True, blank=True)
    reason = models.TextField()
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    last_updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)


class PRDocWorkflow(TimeStampedModel, UUIDAbstractModel):
    # This model will only store latest workflow for each PR
    owner = models.CharField(max_length=512)
    repo = models.CharField(max_length=512)
    pr_no = models.PositiveIntegerField()
    # TODO: add some info to identify different ci/cd runners
    workflow_id = models.CharField(max_length=128)
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    last_updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
