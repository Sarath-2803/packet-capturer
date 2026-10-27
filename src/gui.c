#include "lib.h"
#include "ipv4.h"
#include "ipv6.h"
#include "transport.h"
#include "icmp.h"
#include "arp.h"
#include "stats.h"

#include <gtk/gtk.h>
#include <pcap/pcap.h>

#include <errno.h>
#include <glib/gstdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define APP_ID "io.github.framescope.FrameScope"
#define APP_NAME "FrameScope"
#define PACKET_INFO_LEN 256
#define PACKET_DETAILS_LEN 4096
#define PACKET_SEARCH_LEN 1024
#define MAX_QUEUE_LEN 20000
#define MAX_DRAIN_PER_TICK 2000
#define BATCH_INTERVAL_MS 100

#define DETAILS_PLACEHOLDER \
    "Select a packet to inspect its decoded headers.\n\n" \
    "Ethernet  /  VLAN\n" \
    "IPv4      /  IPv6\n" \
    "TCP       /  UDP\n" \
    "ICMP      /  ICMPv6\n" \
    "ARP"

typedef enum {
    PROTO_OTHER,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_ICMPV6,
    PROTO_ARP,
    PROTO_IPV4,
    PROTO_IPV6
} ProtocolClass;

typedef enum {
    BANNER_INFO,
    BANNER_SUCCESS,
    BANNER_WARNING,
    BANNER_ERROR
} BannerKind;

typedef enum {
    COL_NUMBER,
    COL_TIME,
    COL_SOURCE,
    COL_DESTINATION,
    COL_PROTOCOL,
    COL_LENGTH,
    COL_INFO
} PacketColumn;

typedef struct {
    gboolean promiscuous;
    gint snaplen;
    gint timeout_ms;
    gint max_rows;
    gboolean auto_follow;
    gboolean archive_enabled;
    gint window_width;
    gint window_height;
} AppSettings;

typedef struct {
    char timestamp[32];
    char source[64];
    char destination[64];
    char protocol[24];
    char info[PACKET_INFO_LEN];
    char details[PACKET_DETAILS_LEN];

    guint32 bytes;
    ProtocolClass proto_class;
    gboolean valid_frame;
    gboolean has_l4;
    gboolean is_ipv6;
    guint8 l4_protocol;
    FrameInfo frame;
} PacketUpdate;

typedef struct _PacketRecord {
    GObject parent_instance;

    guint64 number;
    char timestamp[32];
    char source[64];
    char destination[64];
    char protocol[24];
    char info[PACKET_INFO_LEN];
    char details[PACKET_DETAILS_LEN];
    char search[PACKET_SEARCH_LEN];

    guint32 bytes;
    ProtocolClass proto_class;
    gboolean valid_frame;
    gboolean has_l4;
    gboolean is_ipv6;
    guint8 l4_protocol;
    FrameInfo frame;
} PacketRecord;

typedef struct _PacketRecordClass {
    GObjectClass parent_class;
} PacketRecordClass;

GType packet_record_get_type(void);
G_DEFINE_TYPE(PacketRecord, packet_record, G_TYPE_OBJECT)

typedef struct {
    atomic_bool stop_requested;
    GThread *thread;

    char interface_name[256];
    char filter[512];

    gint snaplen;
    gint timeout_ms;
    gboolean promiscuous;
    gboolean archive_enabled;

    char *archive_path;
    char archive_error[PCAP_ERRBUF_SIZE + 128];
    guint64 archived_packets;
    guint64 archived_bytes;
    guint64 queue_dropped;
} CaptureSession;

typedef struct {
    CaptureSession *session;
    char error[1024];
} CaptureFinished;

typedef struct {
    char *name;
    char *description;
} InterfaceEntry;

typedef struct {
    GtkWidget *count;
    GtkWidget *percent;
    GtkWidget *bar;
} DistributionRow;

typedef struct {
    const char *title;
    gboolean expand;
    gint width;
} PacketColumnDef;

static const PacketColumnDef packet_column_defs[] = {
    {"NO.", FALSE, 64},
    {"TIME", FALSE, 128},
    {"SOURCE", TRUE, 0},
    {"DESTINATION", TRUE, 0},
    {"PROTOCOL", FALSE, 112},
    {"LENGTH", FALSE, 82},
    {"INFO", TRUE, 0}
};

/* Widgets */
static GtkWidget *window;
static GtkWidget *nav_buttons[4];
static GtkWidget *interface_dropdown;
static GtkWidget *interface_description;
static GtkWidget *refresh_button;
static GtkWidget *start_button;
static GtkWidget *stop_button;
static GtkWidget *filter_entry;
static GtkWidget *follow_toggle;

static GtkWidget *live_clear_button;
static GtkWidget *live_export_button;
static GtkWidget *history_clear_button;
static GtkWidget *history_export_button;
static GtkWidget *history_search;
static GtkWidget *live_count_label;
static GtkWidget *history_count_label;
static GtkWidget *live_empty_state;
static GtkWidget *history_empty_state;
static GtkWidget *live_column_view;
static GtkWidget *history_column_view;
static GtkWidget *details_view;
static GtkWidget *history_details_view;

static GtkWidget *status_dot;
static GtkWidget *status_label;
static GtkWidget *status_meta;
static GtkWidget *sidebar_dot;
static GtkWidget *sidebar_status;
static GtkWidget *error_revealer;
static GtkWidget *error_label;

static GtkWidget *stat_packets;
static GtkWidget *stat_bytes;
static GtkWidget *stat_rate;
static GtkWidget *stat_duration;

static GtkWidget *stats_page_packets;
static GtkWidget *stats_page_bytes;
static GtkWidget *stats_page_avg_rate;
static GtkWidget *stats_page_duration;
static GtkWidget *stats_page_archive;

static GtkWidget *settings_promisc_switch;
static GtkWidget *settings_snaplen_spin;
static GtkWidget *settings_timeout_spin;
static GtkWidget *settings_maxrows_spin;
static GtkWidget *settings_follow_switch;
static GtkWidget *settings_archive_switch;

static DistributionRow proto_rows[7];
static DistributionRow frame_rows[10];

/* Models and data */
static GtkStringList *interface_model;
static GPtrArray *interface_entries;
static GListStore *packet_store;
static GtkSingleSelection *live_selection;
static GtkSingleSelection *history_selection;
static GtkFilterListModel *history_filter_model;
static GtkFilter *history_filter;
static char *history_needle;

static GAsyncQueue *packet_queue;
static guint batch_timer_id;
static CaptureSession *active_session;

static AppSettings settings;

static guint64 captured_packets;
static guint64 captured_bytes;
static guint64 dropped_packets;

static Stats g_stats;

static gint64 capture_start_us;
static gint64 capture_stop_us;
static gint64 last_rate_us;
static guint64 last_rate_packets;
static guint64 last_rate_bytes;
static double current_pps;
static double current_bps;

static gboolean capture_running;
static gboolean capture_stopping;
static gboolean capture_had_error;

static gboolean pending_close;
static gboolean close_prompt_active;
static gboolean start_prompt_active;
static gboolean syncing_widgets;

static char *archive_path;
static guint64 archive_packets;
static guint64 archive_bytes;
static gboolean archive_exported = TRUE;

/* Function prototypes */
static void update_controls(void);
static void update_counts(void);
static void update_statistics_ui(void);
static void update_status_ui(void);
static void refresh_data_ui(void);
static void set_details(GtkWidget *view, PacketRecord *record);
static void clear_details_views(void);
static void clear_capture_data(void);
static void begin_capture_for_selection(void);
static void follow_latest(void);
static void apply_follow_setting(gboolean enabled, gboolean persist);
static void show_banner(const char *message, BannerKind kind);
static void hide_banner(void);
static void cleanup_archive(void);
static void update_archive_ui(void);
static void save_settings(void);
static void trim_packet_store(void);
static void on_start_clicked(GtkButton *button, gpointer user_data);
static void on_stop_clicked(GtkButton *button, gpointer user_data);
static void on_clear_clicked(GtkButton *button, gpointer user_data);
static void on_export_clicked(GtkButton *button, gpointer user_data);
static void on_refresh_clicked(GtkButton *button, gpointer user_data);
static void on_follow_toggled(GtkCheckButton *button, gpointer user_data);
static void on_history_search_changed(GtkSearchEntry *entry, gpointer user_data);
static const char *selected_interface_name(void);
static gboolean on_close_request(GtkWindow *win, gpointer user_data);
static void request_close_after_capture(void);
static void finalize_close(void);
static void on_reset_settings_clicked(GtkButton *button, gpointer user_data);

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

static GtkWidget *make_label(const char *text, const char *css_class)
{
    GtkWidget *label = gtk_label_new(text);

    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);

    if (css_class != NULL)
        gtk_widget_add_css_class(label, css_class);

    return label;
}

static void set_label_text(GtkWidget *label, const char *text)
{
    if (label != NULL)
        gtk_label_set_text(GTK_LABEL(label), text);
}

static void format_bytes(guint64 bytes, char *out, size_t out_size)
{
    static const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = (double)bytes;
    guint unit = 0;

    while (value >= 1024.0 && unit < G_N_ELEMENTS(units) - 1)
    {
        value /= 1024.0;
        unit++;
    }

    if (unit == 0)
        snprintf(out, out_size, "%" G_GUINT64_FORMAT " B", bytes);
    else
        snprintf(out, out_size, "%.2f %s", value, units[unit]);
}

static void format_rate(double bits_per_second, char *out, size_t out_size)
{
    if (bits_per_second >= 1e9)
        snprintf(out, out_size, "%.2f Gb/s", bits_per_second / 1e9);
    else if (bits_per_second >= 1e6)
        snprintf(out, out_size, "%.2f Mb/s", bits_per_second / 1e6);
    else if (bits_per_second >= 1e3)
        snprintf(out, out_size, "%.1f Kb/s", bits_per_second / 1e3);
    else
        snprintf(out, out_size, "%.0f b/s", bits_per_second);
}

static void format_duration(double seconds, char *out, size_t out_size)
{
    if (seconds < 1.0)
    {
        snprintf(out, out_size, "0s");
        return;
    }

    guint64 total = (guint64)seconds;

    if (total < 60)
        snprintf(out, out_size, "%" G_GUINT64_FORMAT "s", total);
    else if (total < 3600)
        snprintf(out, out_size, "%02" G_GUINT64_FORMAT ":%02" G_GUINT64_FORMAT,
                 total / 60, total % 60);
    else
        snprintf(out, out_size,
                 "%02" G_GUINT64_FORMAT ":%02" G_GUINT64_FORMAT
                 ":%02" G_GUINT64_FORMAT,
                 total / 3600, (total / 60) % 60, total % 60);
}

static double capture_duration_seconds(void)
{
    if (capture_start_us == 0)
        return 0.0;

    gint64 end = capture_running
        ? g_get_monotonic_time()
        : (capture_stop_us > 0 ? capture_stop_us : capture_start_us);

    if (end <= capture_start_us)
        return 0.0;

    return (double)(end - capture_start_us) / 1000000.0;
}

static const char *protocol_css_class(ProtocolClass proto)
{
    switch (proto)
    {
    case PROTO_TCP: return "badge-tcp";
    case PROTO_UDP: return "badge-udp";
    case PROTO_ICMP: return "badge-icmp";
    case PROTO_ICMPV6: return "badge-icmp6";
    case PROTO_ARP: return "badge-arp";
    case PROTO_IPV4: return "badge-ipv4";
    case PROTO_IPV6: return "badge-ipv6";
    case PROTO_OTHER:
    default: return "badge-other";
    }
}

static const char *const badge_classes[] = {
    "badge-tcp",
    "badge-udp",
    "badge-icmp",
    "badge-icmp6",
    "badge-arp",
    "badge-ipv4",
    "badge-ipv6",
    "badge-other",
    NULL
};

static gint clamp_int(gint value, gint minimum, gint maximum)
{
    if (value < minimum)
        return minimum;
    if (value > maximum)
        return maximum;
    return value;
}

/* ------------------------------------------------------------------------- */
/* Packet record                                                             */
/* ------------------------------------------------------------------------- */

static void packet_record_finalize(GObject *object)
{
    G_OBJECT_CLASS(packet_record_parent_class)->finalize(object);
}

static void packet_record_class_init(PacketRecordClass *klass)
{
    G_OBJECT_CLASS(klass)->finalize = packet_record_finalize;
}

static void packet_record_init(PacketRecord *self)
{
    (void)self;
}

static PacketRecord *packet_record_new_from_update(const PacketUpdate *update,
                                                   guint64 number)
{
    PacketRecord *record = g_object_new(packet_record_get_type(), NULL);

    record->number = number;
    g_strlcpy(record->timestamp, update->timestamp, sizeof(record->timestamp));
    g_strlcpy(record->source, update->source, sizeof(record->source));
    g_strlcpy(record->destination, update->destination,
              sizeof(record->destination));
    g_strlcpy(record->protocol, update->protocol, sizeof(record->protocol));
    g_strlcpy(record->info, update->info, sizeof(record->info));
    g_strlcpy(record->details, update->details, sizeof(record->details));

    record->bytes = update->bytes;
    record->proto_class = update->proto_class;
    record->valid_frame = update->valid_frame;
    record->has_l4 = update->has_l4;
    record->is_ipv6 = update->is_ipv6;
    record->l4_protocol = update->l4_protocol;
    record->frame = update->frame;

    snprintf(record->search, sizeof(record->search), "%s %s %s %s",
             record->source, record->destination, record->protocol,
             record->info);
    g_ascii_strdown(record->search, -1);

    return record;
}

/* ------------------------------------------------------------------------- */
/* Settings                                                                  */
/* ------------------------------------------------------------------------- */

static void settings_set_defaults(AppSettings *out)
{
    out->promiscuous = TRUE;
    out->snaplen = 65535;
    out->timeout_ms = 250;
    out->max_rows = 5000;
    out->auto_follow = TRUE;
    out->archive_enabled = TRUE;
    out->window_width = 1360;
    out->window_height = 860;
}

static char *settings_file_path(void)
{
    return g_build_filename(g_get_user_config_dir(), "framescope",
                            "settings.ini", NULL);
}

static gint keyfile_get_int(GKeyFile *file, const char *group,
                            const char *key, gint fallback)
{
    GError *error = NULL;
    gint value = g_key_file_get_integer(file, group, key, &error);

    if (error != NULL)
    {
        g_error_free(error);
        return fallback;
    }

    return value;
}

static gboolean keyfile_get_bool(GKeyFile *file, const char *group,
                                 const char *key, gboolean fallback)
{
    GError *error = NULL;
    gboolean value = g_key_file_get_boolean(file, group, key, &error);

    if (error != NULL)
    {
        g_error_free(error);
        return fallback;
    }

    return value;
}

static void load_settings(void)
{
    settings_set_defaults(&settings);

    char *path = settings_file_path();
    GKeyFile *file = g_key_file_new();

    if (g_key_file_load_from_file(file, path, G_KEY_FILE_NONE, NULL))
    {
        settings.promiscuous =
            keyfile_get_bool(file, "capture", "promiscuous",
                             settings.promiscuous);
        settings.archive_enabled =
            keyfile_get_bool(file, "capture", "archive",
                             settings.archive_enabled);
        settings.snaplen =
            keyfile_get_int(file, "capture", "snaplen", settings.snaplen);
        settings.timeout_ms =
            keyfile_get_int(file, "capture", "timeout",
                            settings.timeout_ms);
        settings.max_rows =
            keyfile_get_int(file, "display", "max_rows", settings.max_rows);
        settings.auto_follow =
            keyfile_get_bool(file, "display", "auto_follow",
                             settings.auto_follow);
        settings.window_width =
            keyfile_get_int(file, "window", "width", settings.window_width);
        settings.window_height =
            keyfile_get_int(file, "window", "height", settings.window_height);
    }

    g_key_file_free(file);
    g_free(path);

    settings.snaplen = clamp_int(settings.snaplen, 64, 262144);
    settings.timeout_ms = clamp_int(settings.timeout_ms, 50, 5000);
    settings.max_rows = clamp_int(settings.max_rows, 100, 200000);
    settings.window_width = clamp_int(settings.window_width, 900, 4000);
    settings.window_height = clamp_int(settings.window_height, 600, 3000);
}

static void save_settings(void)
{
    if (window != NULL)
    {
        gint width = gtk_widget_get_width(window);
        gint height = gtk_widget_get_height(window);

        if (width > 0)
            settings.window_width = width;
        if (height > 0)
            settings.window_height = height;
    }

    char *path = settings_file_path();
    char *directory = g_path_get_dirname(path);

    g_mkdir_with_parents(directory, 0755);

    GKeyFile *file = g_key_file_new();

    g_key_file_set_boolean(file, "capture", "promiscuous",
                           settings.promiscuous);
    g_key_file_set_boolean(file, "capture", "archive",
                           settings.archive_enabled);
    g_key_file_set_integer(file, "capture", "snaplen", settings.snaplen);
    g_key_file_set_integer(file, "capture", "timeout", settings.timeout_ms);
    g_key_file_set_integer(file, "display", "max_rows", settings.max_rows);
    g_key_file_set_boolean(file, "display", "auto_follow",
                           settings.auto_follow);
    g_key_file_set_integer(file, "window", "width", settings.window_width);
    g_key_file_set_integer(file, "window", "height", settings.window_height);

    g_key_file_save_to_file(file, path, NULL);

    g_key_file_free(file);
    g_free(directory);
    g_free(path);
}

/* ------------------------------------------------------------------------- */
/* Banner and status                                                         */
/* ------------------------------------------------------------------------- */

static void hide_banner(void)
{
    if (error_revealer != NULL)
        gtk_revealer_set_reveal_child(GTK_REVEALER(error_revealer), FALSE);
}

static void show_banner(const char *message, BannerKind kind)
{
    if (error_revealer == NULL || error_label == NULL)
        return;

    static const char *const classes[] = {
        "banner-info", "banner-success", "banner-warning", "banner-error"
    };

    for (size_t i = 0; i < G_N_ELEMENTS(classes); i++)
        gtk_widget_remove_css_class(error_revealer, classes[i]);

    switch (kind)
    {
    case BANNER_SUCCESS:
        gtk_widget_add_css_class(error_revealer, "banner-success");
        break;
    case BANNER_WARNING:
        gtk_widget_add_css_class(error_revealer, "banner-warning");
        break;
    case BANNER_ERROR:
        gtk_widget_add_css_class(error_revealer, "banner-error");
        break;
    case BANNER_INFO:
    default:
        gtk_widget_add_css_class(error_revealer, "banner-info");
        break;
    }

    gtk_label_set_text(GTK_LABEL(error_label), message);
    gtk_revealer_set_reveal_child(GTK_REVEALER(error_revealer), TRUE);
}

static void set_status_state(const char *state_class)
{
    static const char *const classes[] = {
        "status-live", "status-idle", "status-error",
        "status-stopping", "status-ok"
    };

    GtkWidget *targets[] = {
        status_dot, status_label, sidebar_dot, sidebar_status
    };

    for (size_t i = 0; i < G_N_ELEMENTS(targets); i++)
    {
        if (targets[i] == NULL)
            continue;

        for (size_t j = 0; j < G_N_ELEMENTS(classes); j++)
            gtk_widget_remove_css_class(targets[i], classes[j]);

        gtk_widget_add_css_class(targets[i], state_class);
    }
}

static void update_status_ui(void)
{
    char text[320];
    char meta[1024];
    char sidebar[32];

    if (capture_running)
    {
        if (capture_stopping)
        {
            snprintf(text, sizeof(text), "Stopping capture…");
            g_strlcpy(sidebar, "STOPPING", sizeof(sidebar));
            set_status_state("status-stopping");
        }
        else
        {
            snprintf(text, sizeof(text), "Capturing on %s",
                     active_session != NULL
                         ? active_session->interface_name
                         : "interface");
            g_strlcpy(sidebar, "CAPTURING", sizeof(sidebar));
            set_status_state("status-live");
        }

        const char *filter = active_session != NULL
            ? active_session->filter : "";
        char rate[64];
        format_rate(current_bps, rate, sizeof(rate));
        snprintf(meta, sizeof(meta),
                 "%s  ·  %" G_GUINT64_FORMAT " packets  ·  %s  ·  %s",
                 (filter[0] != '\0') ? filter : "all traffic",
                 captured_packets, rate,
                 (active_session != NULL && active_session->archive_enabled)
                     ? "PCAP recording" : "PCAP archive off");
    }
    else if (capture_had_error)
    {
        snprintf(text, sizeof(text), "Capture error");
        g_strlcpy(sidebar, "ERROR", sizeof(sidebar));
        set_status_state("status-error");

        if (archive_path != NULL && archive_packets > 0)
            snprintf(meta, sizeof(meta),
                     "Recovered %" G_GUINT64_FORMAT
                     " packets in the export archive",
                     archive_packets);
        else
            snprintf(meta, sizeof(meta), "Review the message above");
    }
    else
    {
        if (captured_packets > 0)
        {
            snprintf(text, sizeof(text),
                     "Capture stopped  ·  %" G_GUINT64_FORMAT " packets",
                     captured_packets);
            g_strlcpy(sidebar, "STOPPED", sizeof(sidebar));
            set_status_state("status-idle");
        }
        else
        {
            const char *interface_name = selected_interface_name();

            if (interface_name != NULL)
            {
                snprintf(text, sizeof(text), "Ready  ·  %s selected",
                         interface_name);
            }
            else
            {
                snprintf(text, sizeof(text),
                         "Ready  ·  Select an interface to begin");
            }

            g_strlcpy(sidebar, "READY", sizeof(sidebar));
            set_status_state("status-idle");
        }

        if (archive_path != NULL && archive_packets > 0)
        {
            char size[64];
            format_bytes(archive_bytes, size, sizeof(size));
            snprintf(meta, sizeof(meta),
                     "PCAP archive: %" G_GUINT64_FORMAT
                     " packets  ·  %s",
                     archive_packets, size);
        }
        else if (captured_packets > 0)
        {
            snprintf(meta, sizeof(meta), "PCAP archive unavailable");
        }
        else
        {
            snprintf(meta, sizeof(meta), "libpcap  ·  Ethernet capture");
        }
    }

    set_label_text(status_label, text);
    set_label_text(status_meta, meta);
    set_label_text(sidebar_status, sidebar);
}

/* ------------------------------------------------------------------------- */
/* Statistics page helpers                                                   */
/* ------------------------------------------------------------------------- */

static void set_distribution_row(DistributionRow *row, guint64 value,
                                 guint64 total)
{
    if (row == NULL)
        return;

    char count[40];
    char percent[24];
    double fraction = total > 0 ? (double)value / (double)total : 0.0;

    snprintf(count, sizeof(count), "%" G_GUINT64_FORMAT, value);
    snprintf(percent, sizeof(percent), "%.1f%%", fraction * 100.0);

    set_label_text(row->count, count);
    set_label_text(row->percent, percent);

    if (row->bar != NULL)
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(row->bar), fraction);
}

static guint64 subtraction_clamped(guint64 value, guint64 subtract)
{
    return value > subtract ? value - subtract : 0;
}

static void update_statistics_ui(void)
{
    char text[64];
    char bytes_text[64];
    char duration_text[64];
    char rate_text[64];

    double duration = capture_duration_seconds();
    double average_bps = duration > 0.0
        ? ((double)captured_bytes * 8.0) / duration : 0.0;

    snprintf(text, sizeof(text), "%" G_GUINT64_FORMAT, captured_packets);
    format_bytes(captured_bytes, bytes_text, sizeof(bytes_text));
    format_rate(average_bps, rate_text, sizeof(rate_text));
    format_duration(duration, duration_text, sizeof(duration_text));

    set_label_text(stat_packets, text);
    set_label_text(stat_bytes, bytes_text);
    set_label_text(stat_rate, rate_text);
    set_label_text(stat_duration, duration_text);

    set_label_text(stats_page_packets, text);
    set_label_text(stats_page_bytes, bytes_text);
    set_label_text(stats_page_avg_rate, rate_text);
    set_label_text(stats_page_duration, duration_text);

    if (stats_page_archive != NULL)
    {
        char archive_text[256];

        if (archive_path != NULL && archive_packets > 0)
        {
            char size[64];
            format_bytes(archive_bytes, size, sizeof(size));
            snprintf(archive_text, sizeof(archive_text),
                     "%" G_GUINT64_FORMAT " packets  ·  %s%s",
                     archive_packets, size,
                     archive_exported ? "  ·  exported"
                                      : "  ·  not exported");
        }
        else if (capture_running && active_session != NULL &&
                 active_session->archive_enabled)
        {
            snprintf(archive_text, sizeof(archive_text),
                     "Recording current capture to a temporary PCAP file");
        }
        else
        {
            snprintf(archive_text, sizeof(archive_text),
                     "No capture archive available");
        }

        set_label_text(stats_page_archive, archive_text);
    }

    guint64 total = g_stats.total_frames;
    guint64 ip_total = g_stats.ipv4_frames + g_stats.ipv6_frames;
    guint64 l4_total = g_stats.tcp_frames + g_stats.udp_frames +
                       g_stats.icmp_frames + g_stats.icmpv6_frames;
    guint64 other_ip = subtraction_clamped(ip_total, l4_total);
    guint64 non_ip = subtraction_clamped(total,
                                         ip_total + g_stats.arp_frames);

    set_distribution_row(&proto_rows[0], g_stats.tcp_frames, total);
    set_distribution_row(&proto_rows[1], g_stats.udp_frames, total);
    set_distribution_row(&proto_rows[2], g_stats.icmp_frames, total);
    set_distribution_row(&proto_rows[3], g_stats.icmpv6_frames, total);
    set_distribution_row(&proto_rows[4], g_stats.arp_frames, total);
    set_distribution_row(&proto_rows[5], other_ip, total);
    set_distribution_row(&proto_rows[6], non_ip, total);

    set_distribution_row(&frame_rows[0], g_stats.ipv4_frames, total);
    set_distribution_row(&frame_rows[1], g_stats.ipv6_frames, total);
    set_distribution_row(&frame_rows[2], g_stats.arp_frames, total);
    set_distribution_row(&frame_rows[3], g_stats.vlan_frames, total);
    set_distribution_row(&frame_rows[4], g_stats.unicast_frames, total);
    set_distribution_row(&frame_rows[5], g_stats.multicast_frames, total);
    set_distribution_row(&frame_rows[6], g_stats.broadcast_frames, total);
    set_distribution_row(&frame_rows[7], g_stats.ethernet_ii_frames, total);
    set_distribution_row(&frame_rows[8], g_stats.ieee_8023_frames, total);
    set_distribution_row(&frame_rows[9], g_stats.unknown_frames, total);
}

/* ------------------------------------------------------------------------- */
/* Data model and live updates                                               */
/* ------------------------------------------------------------------------- */

static void trim_packet_store(void)
{
    if (packet_store == NULL)
        return;

    guint count = g_list_model_get_n_items(G_LIST_MODEL(packet_store));

    while ((gint)count > settings.max_rows)
    {
        g_list_store_remove(packet_store, 0);
        count--;
    }
}

static void process_packet_update(PacketUpdate *update)
{
    captured_packets++;
    captured_bytes += update->bytes;

    if (update->valid_frame)
    {
        stats_record(&g_stats, &update->frame);

        if (update->has_l4)
            stats_record_protocol(&g_stats, update->l4_protocol,
                                  update->is_ipv6);
    }

    PacketRecord *record = packet_record_new_from_update(update,
                                                          captured_packets);

    g_list_store_append(packet_store, record);
    g_object_unref(record);

    trim_packet_store();
    g_free(update);
}

static guint drain_queue(guint limit)
{
    guint processed = 0;
    PacketUpdate *update = NULL;

    while ((limit == 0 || processed < limit) &&
           (update = g_async_queue_try_pop(packet_queue)) != NULL)
    {
        process_packet_update(update);
        processed++;
    }

    return processed;
}

static void update_rate(void)
{
    if (!capture_running)
    {
        current_pps = 0.0;
        current_bps = 0.0;
        return;
    }

    gint64 now = g_get_monotonic_time();
    double elapsed = (double)(now - last_rate_us) / 1000000.0;

    if (elapsed >= 0.20)
    {
        guint64 packet_delta = captured_packets - last_rate_packets;
        guint64 byte_delta = captured_bytes - last_rate_bytes;

        current_pps = (double)packet_delta / elapsed;
        current_bps = ((double)byte_delta * 8.0) / elapsed;

        last_rate_us = now;
        last_rate_packets = captured_packets;
        last_rate_bytes = captured_bytes;
    }
}

static void follow_latest(void)
{
    if (live_column_view == NULL || live_selection == NULL)
        return;

    guint count = g_list_model_get_n_items(G_LIST_MODEL(packet_store));

    if (count == 0)
        return;

    gtk_single_selection_set_selected(live_selection, count - 1);
    gtk_column_view_scroll_to(GTK_COLUMN_VIEW(live_column_view),
                              count - 1, NULL, GTK_LIST_SCROLL_NONE, NULL);
}

static void update_archive_ui(void)
{
    gboolean can_export = !capture_running && archive_path != NULL &&
                          archive_packets > 0;

    if (live_export_button != NULL)
        gtk_widget_set_sensitive(live_export_button, can_export);
    if (history_export_button != NULL)
        gtk_widget_set_sensitive(history_export_button, can_export);

    gboolean can_clear = captured_packets > 0 ||
        g_list_model_get_n_items(G_LIST_MODEL(packet_store)) > 0;

    if (live_clear_button != NULL)
        gtk_widget_set_sensitive(live_clear_button, can_clear);
    if (history_clear_button != NULL)
        gtk_widget_set_sensitive(history_clear_button, can_clear);
}

static void update_counts(void)
{
    guint total = g_list_model_get_n_items(G_LIST_MODEL(packet_store));
    guint matching = total;

    if (history_filter_model != NULL)
        matching = g_list_model_get_n_items(
            G_LIST_MODEL(history_filter_model));

    char live_text[192];
    char history_text[192];

    snprintf(live_text, sizeof(live_text),
             "%u shown  ·  %" G_GUINT64_FORMAT " captured%s",
             total, captured_packets,
             dropped_packets > 0 ? "  ·  UI dropped packets" : "");
    snprintf(history_text, sizeof(history_text),
             "%u matching  ·  %u in session", matching, total);

    set_label_text(live_count_label, live_text);
    set_label_text(history_count_label, history_text);

    if (live_empty_state != NULL)
        gtk_widget_set_visible(live_empty_state, total == 0);
    if (history_empty_state != NULL)
        gtk_widget_set_visible(history_empty_state, matching == 0);

    update_archive_ui();
}

static const char *selected_interface_name(void);

static void update_controls(void)
{
    const char *interface_name = selected_interface_name();

    if (interface_dropdown != NULL)
        gtk_widget_set_sensitive(interface_dropdown, !capture_running);
    if (refresh_button != NULL)
        gtk_widget_set_sensitive(refresh_button, !capture_running);
    if (filter_entry != NULL)
        gtk_widget_set_sensitive(filter_entry, !capture_running);
    if (start_button != NULL)
        gtk_widget_set_sensitive(start_button,
                                 !capture_running && interface_name != NULL);
    if (stop_button != NULL)
        gtk_widget_set_sensitive(stop_button,
                                 capture_running && !capture_stopping);

    update_archive_ui();
}

static void refresh_data_ui(void)
{
    update_counts();
    update_statistics_ui();
    update_status_ui();
    update_controls();
}

static gboolean on_batch_tick(gpointer user_data)
{
    (void)user_data;

    guint processed = drain_queue(MAX_DRAIN_PER_TICK);

    update_rate();
    refresh_data_ui();

    if (processed > 0 && settings.auto_follow)
        follow_latest();

    return G_SOURCE_CONTINUE;
}

/* ------------------------------------------------------------------------- */
/* Packet decoding                                                           */
/* ------------------------------------------------------------------------- */

static void copy_details(PacketUpdate *out, GString *details)
{
    g_strlcpy(out->details, details->str, sizeof(out->details));
    g_string_free(details, TRUE);
}

static ProtocolClass protocol_class_from_ip(uint8_t protocol, gboolean is_ipv6)
{
    switch (protocol)
    {
    case 6: return PROTO_TCP;
    case 17: return PROTO_UDP;
    case 1:
        return is_ipv6 ? PROTO_ICMPV6 : PROTO_ICMP;
    case 58:
        return is_ipv6 ? PROTO_ICMPV6 : PROTO_ICMP;
    default:
        return is_ipv6 ? PROTO_IPV6 : PROTO_IPV4;
    }
}

static void append_transport_details(GString *details,
                                     const uint8_t *transport_data,
                                     size_t captured_payload,
                                     uint8_t protocol, gboolean is_ipv6,
                                     PacketUpdate *out)
{
    TransportInfo transport;

    if (protocol == 6 &&
        decode_tcp(transport_data, captured_payload, &transport))
    {
        char flags[64];
        tcp_flags_string(transport.tcp_flags, flags, sizeof(flags));

        g_strlcpy(out->protocol, "TCP", sizeof(out->protocol));
        out->proto_class = PROTO_TCP;

        snprintf(out->info, sizeof(out->info),
                 "%u → %u  [%s]  Seq=%u Ack=%u",
                 transport.src_port, transport.dst_port, flags,
                 transport.tcp_sequence, transport.tcp_acknowledgment);

        g_string_append_printf(details,
                               "\nTCP\n"
                               "  Source port     : %u\n"
                               "  Destination port: %u\n"
                               "  Flags           : %s\n"
                               "  Sequence        : %u\n"
                               "  Acknowledgment  : %u\n"
                               "  Header length   : %u bytes\n",
                               transport.src_port, transport.dst_port,
                               flags, transport.tcp_sequence,
                               transport.tcp_acknowledgment,
                               transport.tcp_header_length);
        return;
    }

    if (protocol == 17 &&
        decode_udp(transport_data, captured_payload, &transport))
    {
        guint16 udp_length = captured_payload >= 6
            ? (guint16)((transport_data[4] << 8) | transport_data[5])
            : 0;

        g_strlcpy(out->protocol, "UDP", sizeof(out->protocol));
        out->proto_class = PROTO_UDP;

        snprintf(out->info, sizeof(out->info),
                 "%u → %u  Len=%u", transport.src_port,
                 transport.dst_port, udp_length);

        g_string_append_printf(details,
                               "\nUDP\n"
                               "  Source port     : %u\n"
                               "  Destination port: %u\n"
                               "  Length          : %u bytes\n",
                               transport.src_port, transport.dst_port,
                               udp_length);
        return;
    }

    if ((protocol == 1 || protocol == 58) && captured_payload >= 4)
    {
        ICMPInfo icmp;

        if (decode_icmp(transport_data, captured_payload, &icmp))
        {
            gboolean icmpv6 = is_ipv6 || protocol == 58;

            g_strlcpy(out->protocol, icmpv6 ? "ICMPv6" : "ICMP",
                      sizeof(out->protocol));
            out->proto_class = icmpv6 ? PROTO_ICMPV6 : PROTO_ICMP;

            snprintf(out->info, sizeof(out->info),
                     "%s (type %u, code %u)",
                     icmp_type_name(icmp.type, icmpv6), icmp.type,
                     icmp.code);

            g_string_append_printf(details,
                                   "\n%s\n"
                                   "  Type            : %u (%s)\n"
                                   "  Code            : %u\n"
                                   "  Checksum        : 0x%04X\n",
                                   icmpv6 ? "ICMPv6" : "ICMP", icmp.type,
                                   icmp_type_name(icmp.type, icmpv6),
                                   icmp.code, icmp.checksum);
        }
    }
}

static void apply_vlan_prefix(PacketUpdate *out, const FrameInfo *frame)
{
    if (frame->vlan_count == 0)
        return;

    char body[PACKET_INFO_LEN];
    g_strlcpy(body, out->info, sizeof(body));

    if (frame->vlan_count == 1)
        snprintf(out->info, sizeof(out->info), "[VLAN %u] %.200s",
                 frame->vlan_ids[0], body);
    else
        snprintf(out->info, sizeof(out->info), "[VLAN %u +%zu] %.200s",
                 frame->vlan_ids[0], frame->vlan_count - 1, body);
}

static void decode_arp_packet(const uint8_t *payload, size_t remaining,
                              PacketUpdate *out, GString *details)
{
    ARPInfo arp;

    if (!decode_arp(payload, remaining, &arp))
    {
        g_strlcpy(out->protocol, "ARP", sizeof(out->protocol));
        g_strlcpy(out->info, "Invalid or unsupported ARP packet",
                  sizeof(out->info));
        g_string_append(details,
                        "\nARP\n  Invalid or unsupported ARP packet.\n");
        return;
    }

    char sender_ip[16];
    char target_ip[16];
    char sender_mac[18];
    char target_mac[18];

    format_arp_ipv4(arp.sender_ip, sender_ip);
    format_arp_ipv4(arp.target_ip, target_ip);
    format_mac(arp.sender_mac, sender_mac);
    format_mac(arp.target_mac, target_mac);

    g_strlcpy(out->source, sender_ip, sizeof(out->source));
    g_strlcpy(out->destination, target_ip, sizeof(out->destination));
    g_strlcpy(out->protocol, "ARP", sizeof(out->protocol));
    out->proto_class = PROTO_ARP;

    if (arp.operation == 1)
        snprintf(out->info, sizeof(out->info),
                 "Who has %s?  Tell %s", target_ip, sender_ip);
    else if (arp.operation == 2)
        snprintf(out->info, sizeof(out->info),
                 "%s is at %s", sender_ip, sender_mac);
    else
        snprintf(out->info, sizeof(out->info), "%s  %s → %s",
                 arp_operation_name(arp.operation), sender_ip, target_ip);

    g_string_append_printf(details,
                           "\nARP\n"
                           "  Operation       : %s (%u)\n"
                           "  Hardware type   : %u\n"
                           "  Protocol type   : 0x%04X\n"
                           "  Sender MAC      : %s\n"
                           "  Sender IP       : %s\n"
                           "  Target MAC      : %s\n"
                           "  Target IP       : %s\n",
                           arp_operation_name(arp.operation), arp.operation,
                           arp.hardware_type, arp.protocol_type, sender_mac,
                           sender_ip, target_mac, target_ip);
}

static void packet_to_update(const struct pcap_pkthdr *header,
                             const u_char *packet, PacketUpdate *out)
{
    memset(out, 0, sizeof(*out));
    out->bytes = header->caplen;

    struct tm local_time;
    time_t seconds = (time_t)header->ts.tv_sec;
    localtime_r(&seconds, &local_time);

    char clock_text[16];
    char full_time[32];
    strftime(clock_text, sizeof(clock_text), "%H:%M:%S", &local_time);
    strftime(full_time, sizeof(full_time), "%Y-%m-%d %H:%M:%S", &local_time);

    snprintf(out->timestamp, sizeof(out->timestamp), "%s.%06ld",
             clock_text, (long)header->ts.tv_usec);

    GString *details = g_string_new(NULL);

    g_string_append_printf(details, "Timestamp   : %s.%06ld\n",
                           full_time, (long)header->ts.tv_usec);
    g_string_append_printf(details, "Captured    : %u bytes\n",
                           header->caplen);
    if (header->len != header->caplen)
        g_string_append_printf(details, "Wire length : %u bytes\n",
                               header->len);
    g_string_append_c(details, '\n');

    FrameInfo frame;

    if (!decode_ethernet(packet, header->caplen, &frame))
    {
        g_strlcpy(out->source, "—", sizeof(out->source));
        g_strlcpy(out->destination, "—", sizeof(out->destination));
        g_strlcpy(out->protocol, "Unknown", sizeof(out->protocol));
        g_strlcpy(out->info, "Malformed or truncated Ethernet frame",
                  sizeof(out->info));
        out->proto_class = PROTO_OTHER;

        g_string_append(details,
                        "Ethernet\n"
                        "  Unable to decode a valid Ethernet header.\n");
        copy_details(out, details);
        return;
    }

    out->valid_frame = TRUE;
    out->frame = frame;

    char src_mac[18];
    char dst_mac[18];
    format_mac(frame.src, src_mac);
    format_mac(frame.dst, dst_mac);

    g_strlcpy(out->source, src_mac, sizeof(out->source));
    g_strlcpy(out->destination, dst_mac, sizeof(out->destination));
    g_strlcpy(out->protocol,
              ether_type_name(frame.ether_type, frame.is_8023_length),
              sizeof(out->protocol));
    out->proto_class = PROTO_OTHER;

    g_string_append_printf(details,
                           "Ethernet\n"
                           "  Source MAC      : %s\n"
                           "  Destination MAC : %s (%s)\n"
                           "  EtherType       : %s (0x%04X)\n",
                           src_mac, dst_mac,
                           mac_type_name(frame.dst_mac_type),
                           ether_type_name(frame.ether_type,
                                           frame.is_8023_length),
                           frame.ether_type);

    if (frame.vlan_count > 0)
    {
        g_string_append(details, "\nVLAN\n");
        for (size_t i = 0; i < frame.vlan_count; i++)
            g_string_append_printf(details,
                                   "  Tag %zu           : VLAN %u\n",
                                   i + 1, frame.vlan_ids[i]);
    }

    if (frame.is_8023_length)
    {
        g_strlcpy(out->protocol, "IEEE 802.3", sizeof(out->protocol));
        snprintf(out->info, sizeof(out->info),
                 "802.3 payload length %u", frame.ether_type);
        g_string_append_printf(details,
                               "\nIEEE 802.3\n"
                               "  Payload length  : %u bytes\n",
                               frame.ether_type);
        copy_details(out, details);
        return;
    }

    if (frame.payload_offset > header->caplen)
    {
        snprintf(out->info, sizeof(out->info),
                 "Truncated frame payload");
        g_string_append(details,
                        "\n[Frame is truncated before the network payload]\n");
        copy_details(out, details);
        return;
    }

    const uint8_t *payload = packet + frame.payload_offset;
    size_t remaining = header->caplen - frame.payload_offset;

    if (frame.ether_type == 0x0800)
    {
        IPv4Info ip;

        if (!decode_ipv4(payload, remaining, &ip))
        {
            g_strlcpy(out->protocol, "IPv4", sizeof(out->protocol));
            g_strlcpy(out->info, "Invalid or truncated IPv4 header",
                      sizeof(out->info));
            g_string_append(details,
                            "\nIPv4\n  Invalid or truncated IPv4 header.\n");
            copy_details(out, details);
            return;
        }

        char src_ip[16];
        char dst_ip[16];
        format_ipv4_address(ip.src_addr, src_ip);
        format_ipv4_address(ip.dst_addr, dst_ip);

        g_strlcpy(out->source, src_ip, sizeof(out->source));
        g_strlcpy(out->destination, dst_ip, sizeof(out->destination));
        out->is_ipv6 = FALSE;
        out->l4_protocol = ip.protocol;
        out->has_l4 = (ip.protocol == 6 || ip.protocol == 17 ||
                       ip.protocol == 1);
        out->proto_class = protocol_class_from_ip(ip.protocol, FALSE);

        g_strlcpy(out->protocol, ipv4_protocol_name(ip.protocol),
                  sizeof(out->protocol));

        snprintf(out->info, sizeof(out->info), "%s → %s", src_ip, dst_ip);

        g_string_append_printf(details,
                               "\nIPv4\n"
                               "  Source          : %s\n"
                               "  Destination     : %s\n"
                               "  Header length   : %u bytes\n"
                               "  Total length    : %u bytes\n"
                               "  Identification  : 0x%04X\n"
                               "  Flags/Fragment  : 0x%04X\n"
                               "  TTL             : %u\n"
                               "  Protocol        : %s (%u)\n",
                               src_ip, dst_ip, ip.header_length,
                               ip.total_length, ip.identification,
                               ip.flags_fragment, ip.ttl,
                               ipv4_protocol_name(ip.protocol),
                               ip.protocol);

        size_t ip_payload = ip.total_length >= ip.header_length
            ? (size_t)(ip.total_length - ip.header_length) : 0;
        size_t captured_payload = remaining > ip.header_length
            ? remaining - ip.header_length : 0;

        if (captured_payload > ip_payload)
            captured_payload = ip_payload;

        gboolean fragmented = (ip.flags_fragment & 0x1FFF) != 0;

        if (fragmented)
        {
            g_string_append(details,
                            "\n[Non-initial fragment: transport header "
                            "not decoded]\n");
        }
        else if (captured_payload > 0)
        {
            append_transport_details(details, payload + ip.header_length,
                                     captured_payload, ip.protocol, FALSE,
                                     out);

            if (out->proto_class == PROTO_IPV4)
                snprintf(out->info, sizeof(out->info),
                         "IPv4 payload: %s",
                         ipv4_protocol_name(ip.protocol));
        }

        apply_vlan_prefix(out, &frame);
        copy_details(out, details);
        return;
    }

    if (frame.ether_type == 0x86DD)
    {
        IPv6Info ip6;

        if (!decode_ipv6(payload, remaining, &ip6))
        {
            g_strlcpy(out->protocol, "IPv6", sizeof(out->protocol));
            g_strlcpy(out->info, "Invalid or truncated IPv6 header",
                      sizeof(out->info));
            g_string_append(details,
                            "\nIPv6\n  Invalid or truncated IPv6 header.\n");
            copy_details(out, details);
            return;
        }

        char src_ip[40];
        char dst_ip[40];
        format_ipv6_address(ip6.src_addr, src_ip);
        format_ipv6_address(ip6.dst_addr, dst_ip);

        g_strlcpy(out->source, src_ip, sizeof(out->source));
        g_strlcpy(out->destination, dst_ip, sizeof(out->destination));
        out->is_ipv6 = TRUE;
        out->l4_protocol = ip6.next_header;
        out->has_l4 = (ip6.next_header == 6 || ip6.next_header == 17 ||
                       ip6.next_header == 58);
        out->proto_class = protocol_class_from_ip(ip6.next_header, TRUE);

        g_strlcpy(out->protocol, ipv6_next_header_name(ip6.next_header),
                  sizeof(out->protocol));

        snprintf(out->info, sizeof(out->info), "%s → %s", src_ip, dst_ip);

        g_string_append_printf(details,
                               "\nIPv6\n"
                               "  Source          : %s\n"
                               "  Destination     : %s\n"
                               "  Hop limit       : %u\n"
                               "  Payload length  : %u bytes\n"
                               "  Next header     : %s (%u)\n",
                               src_ip, dst_ip, ip6.hop_limit,
                               ip6.payload_length,
                               ipv6_next_header_name(ip6.next_header),
                               ip6.next_header);

        size_t captured_payload = remaining > 40 ? remaining - 40 : 0;

        if (captured_payload > ip6.payload_length)
            captured_payload = ip6.payload_length;

        gboolean extension_header = (ip6.next_header == 0 ||
                                     ip6.next_header == 43 ||
                                     ip6.next_header == 44 ||
                                     ip6.next_header == 60);

        if (extension_header)
        {
            snprintf(out->info, sizeof(out->info),
                     "%s → %s  [%s header]", src_ip, dst_ip,
                     ipv6_next_header_name(ip6.next_header));
            g_string_append_printf(details,
                                   "\n[%s header: later headers are not "
                                   "decoded]\n",
                                   ipv6_next_header_name(ip6.next_header));
        }
        else if (captured_payload > 0)
        {
            append_transport_details(details, payload + 40,
                                     captured_payload, ip6.next_header,
                                     TRUE, out);

            if (out->proto_class == PROTO_IPV6)
                snprintf(out->info, sizeof(out->info),
                         "%s → %s  Next: %s", src_ip, dst_ip,
                         ipv6_next_header_name(ip6.next_header));
        }

        apply_vlan_prefix(out, &frame);
        copy_details(out, details);
        return;
    }

    if (frame.ether_type == 0x0806)
    {
        decode_arp_packet(payload, remaining, out, details);
        apply_vlan_prefix(out, &frame);
        copy_details(out, details);
        return;
    }

    snprintf(out->info, sizeof(out->info), "EtherType 0x%04X",
             frame.ether_type);
    g_string_append_printf(details,
                           "\nPayload\n"
                           "  Undecoded EtherType 0x%04X (%zu bytes)\n",
                           frame.ether_type, remaining);

    apply_vlan_prefix(out, &frame);
    copy_details(out, details);
}

/* ------------------------------------------------------------------------- */
/* Details and selection                                                     */
/* ------------------------------------------------------------------------- */

static void set_details(GtkWidget *view, PacketRecord *record)
{
    if (view == NULL)
        return;

    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

    if (record == NULL)
    {
        gtk_text_buffer_set_text(buffer, DETAILS_PLACEHOLDER, -1);
        return;
    }

    GString *text = g_string_sized_new(512 + strlen(record->details));

    g_string_append_printf(text,
                           "PACKET #%" G_GUINT64_FORMAT
                           "   %s   %u bytes\n",
                           record->number, record->protocol,
                           record->bytes);
    g_string_append(text,
                    "----------------------------------------\n");
    g_string_append(text, record->details);

    gtk_text_buffer_set_text(buffer, text->str, -1);
    g_string_free(text, TRUE);
}

static void clear_details_views(void)
{
    set_details(details_view, NULL);
    set_details(history_details_view, NULL);
}

static void on_live_selection_changed(GObject *object, GParamSpec *pspec,
                                      gpointer user_data)
{
    (void)pspec;
    (void)user_data;

    GtkSingleSelection *selection = GTK_SINGLE_SELECTION(object);
    PacketRecord *record = gtk_single_selection_get_selected_item(selection);

    set_details(details_view, record);

    if (record != NULL && capture_running && settings.auto_follow)
    {
        guint selected = gtk_single_selection_get_selected(selection);
        GListModel *model = gtk_single_selection_get_model(selection);
        guint count = g_list_model_get_n_items(model);

        if (selected != GTK_INVALID_LIST_POSITION &&
            count > 0 && selected + 1 < count)
        {
            apply_follow_setting(FALSE, TRUE);
        }
    }
}

static void on_history_selection_changed(GObject *object, GParamSpec *pspec,
                                         gpointer user_data)
{
    (void)pspec;
    (void)user_data;

    PacketRecord *record = gtk_single_selection_get_selected_item(
        GTK_SINGLE_SELECTION(object));

    set_details(history_details_view, record);
}

static void apply_follow_setting(gboolean enabled, gboolean persist)
{
    settings.auto_follow = enabled;

    syncing_widgets = TRUE;
    if (follow_toggle != NULL)
        gtk_check_button_set_active(GTK_CHECK_BUTTON(follow_toggle), enabled);
    if (settings_follow_switch != NULL)
        gtk_switch_set_active(GTK_SWITCH(settings_follow_switch), enabled);
    syncing_widgets = FALSE;

    if (persist)
        save_settings();

    if (enabled && capture_running)
        follow_latest();
}

static void on_follow_toggled(GtkCheckButton *button, gpointer user_data)
{
    (void)user_data;

    if (syncing_widgets)
        return;

    apply_follow_setting(gtk_check_button_get_active(button), TRUE);
}

static void on_history_search_changed(GtkSearchEntry *entry, gpointer user_data)
{
    (void)user_data;

    g_free(history_needle);

    const char *text = gtk_editable_get_text(GTK_EDITABLE(entry));
    history_needle = (text != NULL && text[0] != '\0')
        ? g_ascii_strdown(text, -1) : NULL;

    gtk_filter_changed(history_filter, GTK_FILTER_CHANGE_DIFFERENT);
    update_counts();
}

/* ------------------------------------------------------------------------- */
/* Interfaces                                                                */
/* ------------------------------------------------------------------------- */

static gboolean interface_is_pseudo(const char *name)
{
    static const char *const prefixes[] = {
        "usbmon", "bluetooth-monitor", "nflog", "nfqueue", "dbus-",
        "rpcap", "can", "vcan", "wpan"
    };

    if (name == NULL)
        return TRUE;

    if (strcmp(name, "any") == 0)
        return TRUE;

    for (size_t i = 0; i < G_N_ELEMENTS(prefixes); i++)
    {
        if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0)
            return TRUE;
    }

    return FALSE;
}

static gboolean interface_is_preferred(const char *name)
{
    static const char *const prefixes[] = {
        "en", "eth", "wl", "wlan"
    };

    if (name == NULL)
        return FALSE;

    for (size_t i = 0; i < G_N_ELEMENTS(prefixes); i++)
    {
        if (g_ascii_strncasecmp(name, prefixes[i],
                                strlen(prefixes[i])) == 0)
            return TRUE;
    }

    return FALSE;
}

static void interface_entry_free(gpointer data)
{
    InterfaceEntry *entry = data;

    if (entry == NULL)
        return;

    g_free(entry->name);
    g_free(entry->description);
    g_free(entry);
}

static const char *selected_interface_name(void)
{
    if (interface_dropdown == NULL || interface_entries == NULL)
        return NULL;

    guint selected = gtk_drop_down_get_selected(
        GTK_DROP_DOWN(interface_dropdown));

    if (selected == GTK_INVALID_LIST_POSITION ||
        selected >= interface_entries->len)
        return NULL;

    InterfaceEntry *entry = g_ptr_array_index(interface_entries, selected);

    return entry->name;
}

static void on_interface_changed(GObject *object, GParamSpec *pspec,
                                 gpointer user_data)
{
    (void)pspec;
    (void)user_data;

    const char *name = selected_interface_name();

    if (name == NULL)
    {
        set_label_text(interface_description,
                       "Select a network interface to continue");
        gtk_widget_set_tooltip_text(interface_description, NULL);
        update_controls();
        return;
    }

    guint selected = gtk_drop_down_get_selected(GTK_DROP_DOWN(object));
    InterfaceEntry *entry = g_ptr_array_index(interface_entries, selected);

    char description[384];
    snprintf(description, sizeof(description), "%s — %s",
             entry->name,
             entry->description != NULL && entry->description[0] != '\0'
                 ? entry->description : "Network interface");

    set_label_text(interface_description, description);
    gtk_widget_set_tooltip_text(interface_description, description);
    update_controls();
}

static void load_interfaces(void)
{
    char previous[256] = {0};

    const char *current = selected_interface_name();
    if (current != NULL)
        g_strlcpy(previous, current, sizeof(previous));

    if (interface_entries != NULL)
        g_ptr_array_free(interface_entries, TRUE);

    interface_entries = g_ptr_array_new_with_free_func(interface_entry_free);

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *devices = NULL;

    if (pcap_findalldevs(&devices, errbuf) == -1)
    {
        char message[512];
        snprintf(message, sizeof(message),
                 "Could not list network interfaces: %s",
                 errbuf[0] != '\0' ? errbuf : "unknown error");
        show_banner(message, BANNER_ERROR);

        GtkStringList *model = gtk_string_list_new(NULL);

        if (interface_model != NULL)
            g_object_unref(interface_model);
        interface_model = model;

        gtk_drop_down_set_model(GTK_DROP_DOWN(interface_dropdown),
                                G_LIST_MODEL(interface_model));
        gtk_drop_down_set_selected(GTK_DROP_DOWN(interface_dropdown),
                                   GTK_INVALID_LIST_POSITION);

        set_label_text(interface_description,
                       "No interfaces available. Check libpcap permissions.");
        update_controls();
        return;
    }

    GtkStringList *model = gtk_string_list_new(NULL);

    for (pcap_if_t *dev = devices; dev != NULL; dev = dev->next)
    {
        if (dev->name == NULL || interface_is_pseudo(dev->name))
            continue;

        InterfaceEntry *entry = g_new0(InterfaceEntry, 1);
        entry->name = g_strdup(dev->name);
        entry->description = g_strdup(
            dev->description != NULL && dev->description[0] != '\0'
                ? dev->description : "Network interface");

        g_ptr_array_add(interface_entries, entry);
        gtk_string_list_append(model, dev->name);
    }

    pcap_freealldevs(devices);

    if (interface_model != NULL)
        g_object_unref(interface_model);
    interface_model = model;

    gtk_drop_down_set_model(GTK_DROP_DOWN(interface_dropdown),
                            G_LIST_MODEL(interface_model));

    guint selection = GTK_INVALID_LIST_POSITION;

    if (previous[0] != '\0')
    {
        for (guint i = 0; i < interface_entries->len; i++)
        {
            InterfaceEntry *entry = g_ptr_array_index(interface_entries, i);
            if (strcmp(entry->name, previous) == 0)
            {
                selection = i;
                break;
            }
        }
    }

    if (selection == GTK_INVALID_LIST_POSITION && interface_entries->len > 0)
    {
        for (guint i = 0; i < interface_entries->len; i++)
        {
            InterfaceEntry *entry = g_ptr_array_index(interface_entries, i);

            if (strcmp(entry->name, "lo") != 0 &&
                interface_is_preferred(entry->name))
            {
                selection = i;
                break;
            }
        }

        if (selection == GTK_INVALID_LIST_POSITION)
        {
            for (guint i = 0; i < interface_entries->len; i++)
            {
                InterfaceEntry *entry = g_ptr_array_index(interface_entries, i);

                if (strcmp(entry->name, "lo") != 0)
                {
                    selection = i;
                    break;
                }
            }
        }

        if (selection == GTK_INVALID_LIST_POSITION)
            selection = 0;
    }

    gtk_drop_down_set_selected(GTK_DROP_DOWN(interface_dropdown), selection);
    on_interface_changed(G_OBJECT(interface_dropdown), NULL, NULL);

    if (interface_entries->len == 0)
    {
        set_label_text(interface_description,
                       "No network interfaces found.");
        show_banner("No network interfaces were found. "
                    "Check libpcap capture permissions.", BANNER_WARNING);
    }
}

static void on_refresh_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    if (capture_running)
        return;

    hide_banner();
    load_interfaces();
}

/* ------------------------------------------------------------------------- */
/* Capture worker                                                            */
/* ------------------------------------------------------------------------- */

static gboolean apply_capture_finished(gpointer data);

static gpointer capture_worker(gpointer data)
{
    CaptureSession *session = data;

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char error[1024] = {0};

    pcap_t *handle = pcap_open_live(session->interface_name,
                                    session->snaplen,
                                    session->promiscuous,
                                    session->timeout_ms,
                                    errbuf);

    if (handle == NULL)
    {
        snprintf(error, sizeof(error), "Could not open %s: %s",
                 session->interface_name,
                 errbuf[0] != '\0' ? errbuf : "unknown error");
        goto finished;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        snprintf(error, sizeof(error),
                 "Unsupported link-layer type on %s (Ethernet required)",
                 session->interface_name);
        pcap_close(handle);
        goto finished;
    }

    if (session->filter[0] != '\0')
    {
        struct bpf_program program;

        if (pcap_compile(handle, &program, session->filter, 1,
                         PCAP_NETMASK_UNKNOWN) == -1)
        {
            snprintf(error, sizeof(error), "Invalid capture filter: %.200s",
                     pcap_geterr(handle));
            pcap_close(handle);
            goto finished;
        }

        if (pcap_setfilter(handle, &program) == -1)
        {
            snprintf(error, sizeof(error), "Could not apply filter: %.200s",
                     pcap_geterr(handle));
            pcap_freecode(&program);
            pcap_close(handle);
            goto finished;
        }

        pcap_freecode(&program);
    }

    pcap_t *dead_handle = NULL;
    pcap_dumper_t *dumper = NULL;

    if (session->archive_enabled)
    {
        GError *gerror = NULL;
        char *temporary_path = NULL;
        int fd = g_file_open_tmp("framescope-XXXXXX.pcap",
                                 &temporary_path, &gerror);

        if (fd < 0)
        {
            snprintf(session->archive_error,
                     sizeof(session->archive_error),
                     "Could not create a PCAP archive: %s",
                     gerror != NULL ? gerror->message : "unknown error");
            g_clear_error(&gerror);
        }
        else
        {
            FILE *file = fdopen(fd, "wb");

            if (file == NULL)
            {
                snprintf(session->archive_error,
                         sizeof(session->archive_error),
                         "Could not open the PCAP archive: %s",
                         g_strerror(errno));
                close(fd);
                g_unlink(temporary_path);
            }
            else
            {
                dead_handle = pcap_open_dead(DLT_EN10MB, session->snaplen);

                if (dead_handle == NULL)
                {
                    g_strlcpy(session->archive_error,
                              "Could not initialise the PCAP writer.",
                              sizeof(session->archive_error));
                    fclose(file);
                    g_unlink(temporary_path);
                }
                else
                {
                    dumper = pcap_dump_fopen(dead_handle, file);

                    if (dumper == NULL)
                    {
                        snprintf(session->archive_error,
                                 sizeof(session->archive_error),
                                 "Could not open the PCAP writer: %.160s",
                                 pcap_geterr(dead_handle));
                        pcap_close(dead_handle);
                        dead_handle = NULL;
                        fclose(file);
                        g_unlink(temporary_path);
                    }
                    else
                    {
                        session->archive_path = temporary_path;
                        temporary_path = NULL;
                    }
                }
            }
        }

        g_free(temporary_path);
    }

    while (!atomic_load(&session->stop_requested))
    {
        struct pcap_pkthdr *header = NULL;
        const u_char *packet = NULL;

        int result = pcap_next_ex(handle, &header, &packet);

        if (result == 0)
            continue;

        if (result == -2)
            break;

        if (result == -1)
        {
            snprintf(error, sizeof(error), "Capture error: %.200s",
                     pcap_geterr(handle));
            break;
        }

        if (dumper != NULL && header != NULL && packet != NULL)
        {
            pcap_dump((u_char *)dumper, header, packet);
            session->archived_packets++;
            session->archived_bytes += header->caplen;
        }

        if (header == NULL || packet == NULL)
            continue;

        PacketUpdate *update = g_new0(PacketUpdate, 1);
        packet_to_update(header, packet, update);

        if (g_async_queue_length(packet_queue) >= MAX_QUEUE_LEN)
        {
            session->queue_dropped++;
            g_free(update);
        }
        else
        {
            g_async_queue_push(packet_queue, update);
        }
    }

    if (dumper != NULL)
        pcap_dump_close(dumper);
    if (dead_handle != NULL)
        pcap_close(dead_handle);

    pcap_close(handle);

finished:;
    CaptureFinished *finished = g_new0(CaptureFinished, 1);
    finished->session = session;
    g_strlcpy(finished->error, error, sizeof(finished->error));
    g_idle_add(apply_capture_finished, finished);

    return NULL;
}

static gboolean apply_capture_finished(gpointer data)
{
    CaptureFinished *finished = data;
    CaptureSession *session = finished->session;

    if (session->thread != NULL)
    {
        g_thread_join(session->thread);
        session->thread = NULL;
    }

    if (batch_timer_id != 0)
    {
        g_source_remove(batch_timer_id);
        batch_timer_id = 0;
    }

    drain_queue(0);

    capture_running = FALSE;
    capture_stopping = FALSE;
    capture_stop_us = g_get_monotonic_time();
    current_pps = 0.0;
    current_bps = 0.0;

    if (active_session == session)
        active_session = NULL;

    dropped_packets += session->queue_dropped;

    g_free(archive_path);
    archive_path = NULL;
    archive_packets = 0;
    archive_bytes = 0;
    archive_exported = TRUE;

    if (session->archive_path != NULL)
    {
        if (session->archived_packets > 0)
        {
            archive_path = session->archive_path;
            session->archive_path = NULL;
            archive_packets = session->archived_packets;
            archive_bytes = session->archived_bytes;
            archive_exported = FALSE;
        }
        else
        {
            g_unlink(session->archive_path);
            g_free(session->archive_path);
            session->archive_path = NULL;
        }
    }

    if (finished->error[0] != '\0')
    {
        capture_had_error = TRUE;
        show_banner(finished->error, BANNER_ERROR);
    }
    else
    {
        capture_had_error = FALSE;

        if (session->archive_error[0] != '\0')
        {
            show_banner(session->archive_error, BANNER_WARNING);
        }
        else if (session->queue_dropped > 0)
        {
            char message[256];
            snprintf(message, sizeof(message),
                     "The display fell behind and skipped %" G_GUINT64_FORMAT
                     " packet rows. The PCAP archive still contains every "
                     "captured packet.",
                     session->queue_dropped);
            show_banner(message, BANNER_WARNING);
        }
        else if (archive_packets > 0)
        {
            char message[256];
            snprintf(message, sizeof(message),
                     "Capture stopped. %" G_GUINT64_FORMAT
                     " packets are ready to export as a Wireshark PCAP file.",
                     archive_packets);
            show_banner(message, BANNER_SUCCESS);
        }
    }

    g_free(session);
    g_free(finished);

    refresh_data_ui();

    if (pending_close)
    {
        pending_close = FALSE;
        request_close_after_capture();
    }

    return G_SOURCE_REMOVE;
}

/* ------------------------------------------------------------------------- */
/* Capture controls                                                          */
/* ------------------------------------------------------------------------- */

static void clear_capture_data(void)
{
    g_list_store_remove_all(packet_store);
    memset(&g_stats, 0, sizeof(g_stats));

    captured_packets = 0;
    captured_bytes = 0;
    dropped_packets = 0;

    if (capture_running)
    {
        capture_start_us = g_get_monotonic_time();
        last_rate_us = capture_start_us;
        last_rate_packets = 0;
        last_rate_bytes = 0;
        current_pps = 0.0;
        current_bps = 0.0;
    }
    else
    {
        capture_start_us = 0;
        capture_stop_us = 0;
        current_pps = 0.0;
        current_bps = 0.0;
    }

    capture_had_error = FALSE;
    clear_details_views();
    hide_banner();
    refresh_data_ui();
}

static void begin_capture_for_selection(void)
{
    const char *interface_name = selected_interface_name();

    if (interface_name == NULL)
    {
        show_banner("Select a network interface first.", BANNER_WARNING);
        return;
    }

    if (capture_running)
        return;

    cleanup_archive();
    clear_capture_data();

    CaptureSession *session = g_new0(CaptureSession, 1);

    g_strlcpy(session->interface_name, interface_name,
              sizeof(session->interface_name));

    const char *filter = gtk_editable_get_text(GTK_EDITABLE(filter_entry));
    g_strlcpy(session->filter, filter != NULL ? filter : "",
              sizeof(session->filter));

    session->snaplen = settings.snaplen;
    session->timeout_ms = settings.timeout_ms;
    session->promiscuous = settings.promiscuous;
    session->archive_enabled = settings.archive_enabled;
    session->archive_path = NULL;

    atomic_init(&session->stop_requested, false);

    active_session = session;
    capture_running = TRUE;
    capture_stopping = FALSE;
    capture_had_error = FALSE;

    capture_start_us = g_get_monotonic_time();
    capture_stop_us = 0;
    last_rate_us = capture_start_us;
    last_rate_packets = 0;
    last_rate_bytes = 0;
    current_pps = 0.0;
    current_bps = 0.0;

    hide_banner();
    clear_details_views();

    if (batch_timer_id != 0)
        g_source_remove(batch_timer_id);
    batch_timer_id = g_timeout_add(BATCH_INTERVAL_MS, on_batch_tick, NULL);

    refresh_data_ui();

    if (settings.auto_follow)
        apply_follow_setting(TRUE, FALSE);

    session->thread = g_thread_new("framescope-capture",
                                   capture_worker, session);
}

static void on_start_discard_response(GObject *source_object,
                                       GAsyncResult *result,
                                       gpointer user_data)
{
    (void)user_data;

    GtkAlertDialog *dialog = GTK_ALERT_DIALOG(source_object);
    GError *error = NULL;
    int choice = gtk_alert_dialog_choose_finish(dialog, result, &error);

    if (error != NULL)
        g_error_free(error);

    start_prompt_active = FALSE;

    if (choice == 1)
    {
        cleanup_archive();
        begin_capture_for_selection();
    }

    g_object_unref(dialog);
}

static void prompt_start_discard(void)
{
    if (start_prompt_active)
        return;

    start_prompt_active = TRUE;

    GtkAlertDialog *dialog =
        gtk_alert_dialog_new("Discard the previous capture?");

    gtk_alert_dialog_set_detail(
        dialog,
        "The current PCAP archive has not been exported. Starting a new "
        "capture will discard it.");

    const char *buttons[] = {"Cancel", "Discard and Start", NULL};
    gtk_alert_dialog_set_buttons(dialog, buttons);
    gtk_alert_dialog_set_cancel_button(dialog, 0);
    gtk_alert_dialog_set_default_button(dialog, 0);

    gtk_alert_dialog_choose(dialog, GTK_WINDOW(window), NULL,
                            on_start_discard_response, NULL);
}

static void on_start_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    if (capture_running)
        return;

    if (selected_interface_name() == NULL)
    {
        show_banner("Select a network interface first.", BANNER_WARNING);
        return;
    }

    if (archive_path != NULL && archive_packets > 0 && !archive_exported)
    {
        prompt_start_discard();
        return;
    }

    begin_capture_for_selection();
}

static void on_stop_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    if (active_session == NULL || !capture_running || capture_stopping)
        return;

    atomic_store(&active_session->stop_requested, true);
    capture_stopping = TRUE;

    update_status_ui();
    update_controls();
}

/* ------------------------------------------------------------------------- */
/* Clear and export                                                          */
/* ------------------------------------------------------------------------- */

static void on_clear_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    clear_capture_data();
}

static void cleanup_archive(void)
{
    if (capture_running)
        return;

    if (archive_path != NULL)
    {
        g_unlink(archive_path);
        g_free(archive_path);
        archive_path = NULL;
    }

    archive_packets = 0;
    archive_bytes = 0;
    archive_exported = TRUE;

    update_archive_ui();
}

static gboolean verify_pcap_file(const char *path)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_offline(path, errbuf);

    if (handle == NULL)
        return FALSE;

    struct pcap_pkthdr *header = NULL;
    const u_char *packet = NULL;
    int result = pcap_next_ex(handle, &header, &packet);

    pcap_close(handle);

    return result == 1;
}

static void on_export_file_ready(GObject *source_object,
                                 GAsyncResult *result,
                                 gpointer user_data)
{
    char *source_path = user_data;
    GtkFileDialog *dialog = GTK_FILE_DIALOG(source_object);
    GError *error = NULL;

    GFile *destination = gtk_file_dialog_save_finish(dialog, result, &error);

    if (destination == NULL)
    {
        if (error != NULL &&
            !g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
            show_banner(error->message, BANNER_ERROR);
        }

        g_clear_error(&error);
        g_free(source_path);
        g_object_unref(dialog);
        return;
    }

    GFile *source = g_file_new_for_path(source_path);

    if (!g_file_copy(source, destination, G_FILE_COPY_OVERWRITE,
                     NULL, NULL, NULL, &error))
    {
        char message[512];
        snprintf(message, sizeof(message), "Could not export capture: %s",
                 error != NULL ? error->message : "unknown error");
        show_banner(message, BANNER_ERROR);
        g_clear_error(&error);
    }
    else
    {
        char *destination_path = g_file_get_path(destination);

        archive_exported = TRUE;

        char message[768];

        if (destination_path != NULL && verify_pcap_file(destination_path))
        {
            snprintf(message, sizeof(message),
                     "PCAP exported successfully: %" G_GUINT64_FORMAT
                     " packets written to %s",
                     archive_packets, destination_path);
            show_banner(message, BANNER_SUCCESS);
        }
        else
        {
            snprintf(message, sizeof(message),
                     "Capture copied to %s, but the exported PCAP could not "
                     "be verified.",
                     destination_path != NULL ? destination_path
                                              : "the selected file");
            show_banner(message, BANNER_WARNING);
        }

        g_free(destination_path);
        refresh_data_ui();
    }

    g_object_unref(source);
    g_object_unref(destination);
    g_free(source_path);
    g_object_unref(dialog);
}

static void on_export_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    if (capture_running)
    {
        show_banner("Stop the capture before exporting.", BANNER_WARNING);
        return;
    }

    if (archive_path == NULL || archive_packets == 0)
    {
        show_banner("There are no captured packets to export.",
                    BANNER_WARNING);
        return;
    }

    char filename[64];
    time_t now = time(NULL);
    struct tm local_time;
    localtime_r(&now, &local_time);
    strftime(filename, sizeof(filename), "framescope-%Y%m%d-%H%M%S.pcap",
             &local_time);

    GtkFileDialog *dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Export capture for Wireshark");
    gtk_file_dialog_set_accept_label(dialog, "Export PCAP");
    gtk_file_dialog_set_initial_name(dialog, filename);

    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Wireshark capture (*.pcap)");
    gtk_file_filter_add_pattern(filter, "*.pcap");

    GListStore *filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
    g_list_store_append(filters, filter);
    gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters));

    g_object_unref(filters);
    g_object_unref(filter);

    gtk_file_dialog_save(dialog, GTK_WINDOW(window), NULL,
                         on_export_file_ready, g_strdup(archive_path));
}

/* ------------------------------------------------------------------------- */
/* Window close handling                                                     */
/* ------------------------------------------------------------------------- */

static void finalize_close(void)
{
    save_settings();
    cleanup_archive();
    gtk_window_destroy(GTK_WINDOW(window));
}

static void on_close_discard_response(GObject *source_object,
                                      GAsyncResult *result,
                                      gpointer user_data)
{
    (void)user_data;

    GtkAlertDialog *dialog = GTK_ALERT_DIALOG(source_object);
    GError *error = NULL;
    int choice = gtk_alert_dialog_choose_finish(dialog, result, &error);

    if (error != NULL)
        g_error_free(error);

    close_prompt_active = FALSE;

    if (choice == 1)
        finalize_close();
    else
        update_status_ui();

    g_object_unref(dialog);
}

static void prompt_close_discard(void)
{
    if (close_prompt_active)
        return;

    close_prompt_active = TRUE;

    GtkAlertDialog *dialog =
        gtk_alert_dialog_new("Discard the unsaved capture?");

    gtk_alert_dialog_set_detail(
        dialog,
        "The current PCAP archive has not been exported. Export it first "
        "if you want to open these packets in Wireshark later.");

    const char *buttons[] = {"Cancel", "Discard and Quit", NULL};
    gtk_alert_dialog_set_buttons(dialog, buttons);
    gtk_alert_dialog_set_cancel_button(dialog, 0);
    gtk_alert_dialog_set_default_button(dialog, 0);

    gtk_alert_dialog_choose(dialog, GTK_WINDOW(window), NULL,
                            on_close_discard_response, NULL);
}

static void request_close_after_capture(void)
{
    if (archive_path != NULL && archive_packets > 0 && !archive_exported)
        prompt_close_discard();
    else
        finalize_close();
}

static gboolean on_close_request(GtkWindow *win, gpointer user_data)
{
    (void)win;
    (void)user_data;

    if (close_prompt_active)
        return TRUE;

    if (capture_running)
    {
        pending_close = TRUE;

        if (!capture_stopping)
            on_stop_clicked(NULL, NULL);

        return TRUE;
    }

    if (archive_path != NULL && archive_packets > 0 && !archive_exported)
    {
        prompt_close_discard();
        return TRUE;
    }

    finalize_close();
    return TRUE;
}

/* ------------------------------------------------------------------------- */
/* UI construction                                                           */
/* ------------------------------------------------------------------------- */

static GtkWidget *make_stat_card(const char *title, const char *value,
                                 GtkWidget **value_out)
{
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    gtk_widget_add_css_class(card, "stat-card");
    gtk_widget_set_hexpand(card, TRUE);

    GtkWidget *heading = make_label(title, "stat-title");
    GtkWidget *value_label = make_label(value, "stat-value");

    gtk_box_append(GTK_BOX(card), heading);
    gtk_box_append(GTK_BOX(card), value_label);

    if (value_out != NULL)
        *value_out = value_label;

    return card;
}

static void setup_packet_cell(GtkSignalListItemFactory *factory,
                              GtkListItem *item, gpointer user_data)
{
    (void)factory;

    PacketColumn column = (PacketColumn)GPOINTER_TO_INT(user_data);
    GtkWidget *label = gtk_label_new(NULL);

    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_widget_add_css_class(label, "packet-cell");

    switch (column)
    {
    case COL_TIME:
        gtk_widget_add_css_class(label, "cell-time");
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
        break;

    case COL_SOURCE:
    case COL_DESTINATION:
        gtk_widget_add_css_class(label, "cell-address");
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(label, TRUE);
        break;

    case COL_PROTOCOL:
        gtk_widget_add_css_class(label, "badge");
        gtk_label_set_xalign(GTK_LABEL(label), 0.5f);
        break;

    case COL_LENGTH:
        gtk_widget_add_css_class(label, "cell-length");
        break;

    case COL_INFO:
        gtk_widget_add_css_class(label, "cell-info");
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(label, TRUE);
        break;

    case COL_NUMBER:
    default:
        gtk_widget_add_css_class(label, "cell-number");
        break;
    }

    gtk_list_item_set_child(item, label);
}

static void bind_packet_cell(GtkSignalListItemFactory *factory,
                             GtkListItem *item, gpointer user_data)
{
    (void)factory;

    PacketColumn column = (PacketColumn)GPOINTER_TO_INT(user_data);
    PacketRecord *record = gtk_list_item_get_item(item);
    GtkWidget *label = gtk_list_item_get_child(item);

    if (record == NULL || label == NULL)
        return;

    char text[128];

    switch (column)
    {
    case COL_NUMBER:
        snprintf(text, sizeof(text), "%" G_GUINT64_FORMAT, record->number);
        gtk_label_set_text(GTK_LABEL(label), text);
        gtk_widget_set_tooltip_text(label, text);
        break;

    case COL_TIME:
        gtk_label_set_text(GTK_LABEL(label), record->timestamp);
        gtk_widget_set_tooltip_text(label, record->timestamp);
        break;

    case COL_SOURCE:
        gtk_label_set_text(GTK_LABEL(label), record->source);
        gtk_widget_set_tooltip_text(label, record->source);
        break;

    case COL_DESTINATION:
        gtk_label_set_text(GTK_LABEL(label), record->destination);
        gtk_widget_set_tooltip_text(label, record->destination);
        break;

    case COL_PROTOCOL:
        gtk_label_set_text(GTK_LABEL(label), record->protocol);
        gtk_widget_set_tooltip_text(label, record->protocol);

        for (size_t i = 0; badge_classes[i] != NULL; i++)
            gtk_widget_remove_css_class(label, badge_classes[i]);

        gtk_widget_add_css_class(label,
                                 protocol_css_class(record->proto_class));
        break;

    case COL_LENGTH:
        snprintf(text, sizeof(text), "%u B", record->bytes);
        gtk_label_set_text(GTK_LABEL(label), text);
        gtk_widget_set_tooltip_text(label, text);
        break;

    case COL_INFO:
    default:
        gtk_label_set_text(GTK_LABEL(label), record->info);
        gtk_widget_set_tooltip_text(label, record->info);
        break;
    }
}

static GtkWidget *make_empty_state(const char *symbol_text,
                                   const char *title_text,
                                   const char *message_text)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_can_target(box, FALSE);
    gtk_widget_add_css_class(box, "empty-state");

    GtkWidget *symbol = make_label(symbol_text, "empty-symbol");
    GtkWidget *title = make_label(title_text, "empty-title");
    GtkWidget *message = make_label(message_text, "muted");

    gtk_label_set_xalign(GTK_LABEL(symbol), 0.5f);
    gtk_label_set_xalign(GTK_LABEL(title), 0.5f);
    gtk_label_set_xalign(GTK_LABEL(message), 0.5f);
    gtk_label_set_wrap(GTK_LABEL(message), TRUE);
    gtk_label_set_justify(GTK_LABEL(message), GTK_JUSTIFY_CENTER);
    gtk_widget_set_size_request(message, 360, -1);

    gtk_box_append(GTK_BOX(box), symbol);
    gtk_box_append(GTK_BOX(box), title);
    gtk_box_append(GTK_BOX(box), message);

    return box;
}

static GtkWidget *make_packet_view(GtkSingleSelection *selection,
                                   GtkWidget **view_out,
                                   GtkWidget **empty_out,
                                   const char *empty_title,
                                   const char *empty_message)
{
    GtkWidget *view = gtk_column_view_new(GTK_SELECTION_MODEL(selection));

    gtk_widget_add_css_class(view, "data-table");
    gtk_column_view_set_show_row_separators(GTK_COLUMN_VIEW(view), TRUE);
    gtk_column_view_set_show_column_separators(GTK_COLUMN_VIEW(view), FALSE);

    for (size_t i = 0; i < G_N_ELEMENTS(packet_column_defs); i++)
    {
        GtkListItemFactory *factory = gtk_signal_list_item_factory_new();

        g_signal_connect(factory, "setup",
                         G_CALLBACK(setup_packet_cell),
                         GINT_TO_POINTER((gint)i));
        g_signal_connect(factory, "bind",
                         G_CALLBACK(bind_packet_cell),
                         GINT_TO_POINTER((gint)i));

        GtkColumnViewColumn *column = gtk_column_view_column_new(
            packet_column_defs[i].title, factory);

        gtk_column_view_column_set_resizable(column, TRUE);
        gtk_column_view_column_set_expand(column,
                                          packet_column_defs[i].expand);

        if (packet_column_defs[i].width > 0)
            gtk_column_view_column_set_fixed_width(
                column, packet_column_defs[i].width);

        gtk_column_view_append_column(GTK_COLUMN_VIEW(view), column);
    }

    GtkWidget *scroll = gtk_scrolled_window_new();

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);

    GtkWidget *empty = make_empty_state("◌", empty_title, empty_message);
    GtkWidget *overlay = gtk_overlay_new();

    gtk_overlay_set_child(GTK_OVERLAY(overlay), scroll);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), empty);
    gtk_widget_set_vexpand(overlay, TRUE);
    gtk_widget_add_css_class(overlay, "table-overlay");

    *view_out = view;
    *empty_out = empty;

    return overlay;
}

static GtkWidget *make_details_panel(GtkWidget **view_out)
{
    GtkWidget *panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    gtk_widget_add_css_class(panel, "panel");

    GtkWidget *heading = make_label("PACKET INSPECTOR", "section-heading");

    GtkWidget *view = gtk_text_view_new();

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 10);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 10);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(view), 8);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(view), 8);
    gtk_widget_add_css_class(view, "details-view");

    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)),
        DETAILS_PLACEHOLDER, -1);

    GtkWidget *scroll = gtk_scrolled_window_new();

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(
        GTK_SCROLLED_WINDOW(scroll), 130);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);

    gtk_box_append(GTK_BOX(panel), heading);
    gtk_box_append(GTK_BOX(panel), scroll);

    *view_out = view;
    return panel;
}

static GtkWidget *make_page_header(const char *title, const char *subtitle)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);

    gtk_box_append(GTK_BOX(box), make_label(title, "page-title"));
    gtk_box_append(GTK_BOX(box), make_label(subtitle, "page-subtitle"));

    return box;
}

static GtkWidget *make_error_banner(void)
{
    error_revealer = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(error_revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
    gtk_widget_add_css_class(error_revealer, "banner");
    gtk_widget_add_css_class(error_revealer, "banner-error");
    gtk_revealer_set_reveal_child(GTK_REVEALER(error_revealer), FALSE);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    gtk_widget_add_css_class(box, "banner-content");

    error_label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(error_label), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(error_label), TRUE);
    gtk_label_set_selectable(GTK_LABEL(error_label), TRUE);
    gtk_widget_set_hexpand(error_label, TRUE);

    GtkWidget *close_button = gtk_button_new_with_label("Dismiss");

    gtk_widget_add_css_class(close_button, "flat");
    gtk_widget_add_css_class(close_button, "banner-close");
    g_signal_connect_swapped(close_button, "clicked",
                             G_CALLBACK(hide_banner), NULL);

    gtk_box_append(GTK_BOX(box), error_label);
    gtk_box_append(GTK_BOX(box), close_button);

    gtk_revealer_set_child(GTK_REVEALER(error_revealer), box);

    return error_revealer;
}

static GtkWidget *make_live_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);

    gtk_widget_set_margin_top(page, 18);
    gtk_widget_set_margin_bottom(page, 16);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);

    gtk_box_append(GTK_BOX(page),
                   make_page_header("Live Capture",
                                    "Inspect, filter and analyze packets "
                                    "in real time."));

    gtk_box_append(GTK_BOX(page), make_error_banner());

    /* Capture toolbar */
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);

    gtk_widget_add_css_class(toolbar, "toolbar-panel");

    GtkWidget *interface_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    gtk_box_append(GTK_BOX(interface_box),
                   make_label("NETWORK INTERFACE", "section-heading"));

    GtkWidget *interface_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

    interface_dropdown = gtk_drop_down_new(NULL, NULL);
    gtk_widget_set_size_request(interface_dropdown, 285, -1);
    gtk_widget_set_hexpand(interface_dropdown, TRUE);
    gtk_widget_set_tooltip_text(interface_dropdown,
                                "Select the interface to capture from");

    refresh_button = gtk_button_new_from_icon_name("view-refresh-symbolic");
    gtk_widget_set_tooltip_text(refresh_button, "Refresh interface list");
    g_signal_connect(refresh_button, "clicked",
                     G_CALLBACK(on_refresh_clicked), NULL);

    gtk_box_append(GTK_BOX(interface_row), interface_dropdown);
    gtk_box_append(GTK_BOX(interface_row), refresh_button);

    interface_description = make_label(
        "Select a network interface to continue", "muted");
    gtk_label_set_wrap(GTK_LABEL(interface_description), TRUE);

    gtk_box_append(GTK_BOX(interface_box), interface_row);
    gtk_box_append(GTK_BOX(interface_box), interface_description);

    gtk_box_append(GTK_BOX(toolbar), interface_box);

    GtkWidget *filter_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    gtk_box_append(GTK_BOX(filter_box),
                   make_label("CAPTURE FILTER", "section-heading"));

    filter_entry = gtk_entry_new();

    gtk_widget_set_size_request(filter_entry, 240, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(filter_entry),
                                   "e.g. tcp port 443");
    gtk_entry_set_max_length(GTK_ENTRY(filter_entry), 511);
    gtk_widget_set_tooltip_text(filter_entry,
                                "Berkeley Packet Filter applied when the "
                                "capture starts");

    gtk_box_append(GTK_BOX(filter_box), filter_entry);
    gtk_box_append(GTK_BOX(filter_box),
                   make_label("BPF syntax  ·  applied on Start", "muted"));

    gtk_box_append(GTK_BOX(toolbar), filter_box);

    GtkWidget *toolbar_spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    gtk_widget_set_hexpand(toolbar_spacer, TRUE);
    gtk_box_append(GTK_BOX(toolbar), toolbar_spacer);

    GtkWidget *action_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

    gtk_widget_set_valign(action_box, GTK_ALIGN_END);

    start_button = gtk_button_new_with_label("▶  Start");
    gtk_widget_add_css_class(start_button, "suggested-action");
    gtk_widget_set_tooltip_text(start_button, "Start capture (Ctrl+S)");

    stop_button = gtk_button_new_with_label("■  Stop");
    gtk_widget_add_css_class(stop_button, "destructive-action");
    gtk_widget_set_tooltip_text(stop_button, "Stop capture (Ctrl+S)");

    g_signal_connect(start_button, "clicked",
                     G_CALLBACK(on_start_clicked), NULL);
    g_signal_connect(stop_button, "clicked",
                     G_CALLBACK(on_stop_clicked), NULL);

    gtk_box_append(GTK_BOX(action_box), start_button);
    gtk_box_append(GTK_BOX(action_box), stop_button);
    gtk_box_append(GTK_BOX(toolbar), action_box);

    gtk_box_append(GTK_BOX(page), toolbar);

    g_signal_connect(interface_dropdown, "notify::selected-item",
                     G_CALLBACK(on_interface_changed), NULL);

    /* Stat cards */
    GtkWidget *stats_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);

    gtk_box_append(GTK_BOX(stats_row),
                   make_stat_card("PACKETS CAPTURED", "0", &stat_packets));
    gtk_box_append(GTK_BOX(stats_row),
                   make_stat_card("CAPTURED BYTES", "0 B", &stat_bytes));
    gtk_box_append(GTK_BOX(stats_row),
                   make_stat_card("AVERAGE RATE", "0 b/s", &stat_rate));
    gtk_box_append(GTK_BOX(stats_row),
                   make_stat_card("DURATION", "0s", &stat_duration));

    gtk_box_append(GTK_BOX(page), stats_row);

    /* Table + details */
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);

    gtk_widget_set_vexpand(paned, TRUE);
    gtk_paned_set_position(GTK_PANED(paned), 360);
    gtk_paned_set_resize_start_child(GTK_PANED(paned), TRUE);
    gtk_paned_set_shrink_start_child(GTK_PANED(paned), FALSE);
    gtk_paned_set_shrink_end_child(GTK_PANED(paned), TRUE);

    GtkWidget *table_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    gtk_widget_add_css_class(table_panel, "panel");

    GtkWidget *table_header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    GtkWidget *table_title = make_label("CAPTURED PACKETS",
                                        "section-heading");
    live_count_label = make_label("0 shown  ·  0 captured", "muted");

    gtk_box_append(GTK_BOX(table_header), table_title);
    gtk_box_append(GTK_BOX(table_header), live_count_label);

    GtkWidget *table_spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(table_spacer, TRUE);
    gtk_box_append(GTK_BOX(table_header), table_spacer);

    follow_toggle = gtk_check_button_new_with_label("Follow latest");
    gtk_widget_set_tooltip_text(follow_toggle,
                                "Keep the newest packet selected and "
                                "visible");
    gtk_box_append(GTK_BOX(table_header), follow_toggle);

    live_clear_button = gtk_button_new_with_label("Clear");
    gtk_widget_add_css_class(live_clear_button, "pill-button");
    gtk_widget_set_tooltip_text(live_clear_button,
                                "Clear the packet list and statistics "
                                "(PCAP archive is kept)");
    g_signal_connect(live_clear_button, "clicked",
                     G_CALLBACK(on_clear_clicked), NULL);

    live_export_button = gtk_button_new_with_label("Export PCAP");
    gtk_widget_add_css_class(live_export_button, "pill-button");
    gtk_widget_set_tooltip_text(live_export_button,
                                "Save the current capture for Wireshark");
    g_signal_connect(live_export_button, "clicked",
                     G_CALLBACK(on_export_clicked), NULL);

    gtk_box_append(GTK_BOX(table_header), live_clear_button);
    gtk_box_append(GTK_BOX(table_header), live_export_button);

    gtk_box_append(GTK_BOX(table_panel), table_header);
    gtk_box_append(GTK_BOX(table_panel),
                   make_packet_view(live_selection, &live_column_view,
                                    &live_empty_state,
                                    "No packets captured",
                                    "Choose an interface and start a capture "
                                    "to inspect network traffic."));

    GtkWidget *details_panel = make_details_panel(&details_view);

    gtk_paned_set_start_child(GTK_PANED(paned), table_panel);
    gtk_paned_set_end_child(GTK_PANED(paned), details_panel);

    gtk_box_append(GTK_BOX(page), paned);

    g_signal_connect(live_selection, "notify::selected-item",
                     G_CALLBACK(on_live_selection_changed), NULL);
    g_signal_connect(follow_toggle, "toggled",
                     G_CALLBACK(on_follow_toggled), NULL);

    return page;
}

static GtkWidget *make_history_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);

    gtk_widget_set_margin_top(page, 18);
    gtk_widget_set_margin_bottom(page, 16);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);

    gtk_box_append(GTK_BOX(page),
                   make_page_header("Packet History",
                                    "Search and inspect every packet in the "
                                    "current session."));

    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    gtk_widget_add_css_class(toolbar, "toolbar-panel");

    history_search = gtk_search_entry_new();
    gtk_widget_set_size_request(history_search, 340, -1);
    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(history_search),
                                          "Search address, protocol or info…");
    gtk_widget_set_tooltip_text(history_search,
                                "Search the current session (Ctrl+F)");
    gtk_widget_set_hexpand(history_search, TRUE);
    gtk_box_append(GTK_BOX(toolbar), history_search);

    history_count_label = make_label("0 matching  ·  0 in session", "muted");
    gtk_box_append(GTK_BOX(toolbar), history_count_label);

    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(toolbar), spacer);

    history_clear_button = gtk_button_new_with_label("Clear");
    gtk_widget_add_css_class(history_clear_button, "pill-button");
    g_signal_connect(history_clear_button, "clicked",
                     G_CALLBACK(on_clear_clicked), NULL);
    gtk_box_append(GTK_BOX(toolbar), history_clear_button);

    history_export_button = gtk_button_new_with_label("Export PCAP");
    gtk_widget_add_css_class(history_export_button, "pill-button");
    gtk_widget_set_tooltip_text(history_export_button,
                                "Save the current capture for Wireshark");
    g_signal_connect(history_export_button, "clicked",
                     G_CALLBACK(on_export_clicked), NULL);
    gtk_box_append(GTK_BOX(toolbar), history_export_button);

    gtk_box_append(GTK_BOX(page), toolbar);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);

    gtk_widget_set_vexpand(paned, TRUE);
    gtk_paned_set_position(GTK_PANED(paned), 420);
    gtk_paned_set_resize_start_child(GTK_PANED(paned), TRUE);
    gtk_paned_set_shrink_start_child(GTK_PANED(paned), FALSE);
    gtk_paned_set_shrink_end_child(GTK_PANED(paned), TRUE);

    GtkWidget *table_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    gtk_widget_add_css_class(table_panel, "panel");

    gtk_box_append(GTK_BOX(table_panel),
                   make_label("SESSION PACKETS", "section-heading"));
    gtk_box_append(GTK_BOX(table_panel),
                   make_packet_view(history_selection, &history_column_view,
                                    &history_empty_state,
                                    "No packets to display",
                                    "Captured packets will appear here. "
                                    "Use the search field to narrow them."));

    GtkWidget *details_panel = make_details_panel(&history_details_view);

    gtk_paned_set_start_child(GTK_PANED(paned), table_panel);
    gtk_paned_set_end_child(GTK_PANED(paned), details_panel);

    gtk_box_append(GTK_BOX(page), paned);

    g_signal_connect(history_selection, "notify::selected-item",
                     G_CALLBACK(on_history_selection_changed), NULL);
    g_signal_connect(history_search, "search-changed",
                     G_CALLBACK(on_history_search_changed), NULL);

    return page;
}

static void add_distribution_row(GtkGrid *grid, gint row_number,
                                 const char *name, const char *badge_class,
                                 const char *bar_class, DistributionRow *out)
{
    GtkWidget *name_label = gtk_label_new(name);

    gtk_label_set_xalign(GTK_LABEL(name_label), 0.0f);
    gtk_widget_add_css_class(name_label, "badge");
    gtk_widget_add_css_class(name_label, badge_class);
    gtk_widget_set_halign(name_label, GTK_ALIGN_START);

    GtkWidget *count = gtk_label_new("0");
    gtk_label_set_xalign(GTK_LABEL(count), 1.0f);
    gtk_widget_add_css_class(count, "dist-value");
    gtk_widget_set_size_request(count, 66, -1);

    GtkWidget *percent = gtk_label_new("0.0%");
    gtk_label_set_xalign(GTK_LABEL(percent), 1.0f);
    gtk_widget_add_css_class(percent, "muted");
    gtk_widget_set_size_request(percent, 52, -1);

    GtkWidget *bar = gtk_progress_bar_new();

    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(bar), FALSE);
    gtk_widget_set_hexpand(bar, TRUE);
    gtk_widget_add_css_class(bar, "dist-bar");
    gtk_widget_add_css_class(bar, bar_class);

    gtk_grid_attach(grid, name_label, 0, row_number, 1, 1);
    gtk_grid_attach(grid, count, 1, row_number, 1, 1);
    gtk_grid_attach(grid, percent, 2, row_number, 1, 1);
    gtk_grid_attach(grid, bar, 3, row_number, 1, 1);

    out->count = count;
    out->percent = percent;
    out->bar = bar;
}

static GtkWidget *make_distribution_panel(const char *title,
                                          const char *subtitle,
                                          const char *const *names,
                                          const char *const *badges,
                                          const char *const *bars,
                                          DistributionRow *rows,
                                          gint count)
{
    GtkWidget *panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    gtk_widget_add_css_class(panel, "panel");
    gtk_widget_set_hexpand(panel, TRUE);

    gtk_box_append(GTK_BOX(panel), make_label(title, "section-heading"));
    gtk_box_append(GTK_BOX(panel), make_label(subtitle, "muted"));

    GtkWidget *grid = gtk_grid_new();

    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);

    for (gint i = 0; i < count; i++)
        add_distribution_row(GTK_GRID(grid), i, names[i], badges[i],
                             bars[i], &rows[i]);

    gtk_box_append(GTK_BOX(panel), grid);

    return panel;
}

static GtkWidget *make_statistics_page(void)
{
    GtkWidget *scroll = gtk_scrolled_window_new();

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER,
                                   GTK_POLICY_AUTOMATIC);

    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);

    gtk_widget_set_margin_top(page, 18);
    gtk_widget_set_margin_bottom(page, 16);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);

    gtk_box_append(GTK_BOX(page),
                   make_page_header("Statistics",
                                    "Protocol mix, frame types and capture "
                                    "health at a glance."));

    GtkWidget *cards = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);

    gtk_box_append(GTK_BOX(cards),
                   make_stat_card("TOTAL PACKETS", "0",
                                  &stats_page_packets));
    gtk_box_append(GTK_BOX(cards),
                   make_stat_card("TOTAL BYTES", "0 B",
                                  &stats_page_bytes));
    gtk_box_append(GTK_BOX(cards),
                   make_stat_card("AVERAGE RATE", "0 b/s",
                                  &stats_page_avg_rate));
    gtk_box_append(GTK_BOX(cards),
                   make_stat_card("DURATION", "0s",
                                  &stats_page_duration));

    gtk_box_append(GTK_BOX(page), cards);

    static const char *const proto_names[] = {
        "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "Other IP", "Non-IP"
    };
    static const char *const proto_badges[] = {
        "badge-tcp", "badge-udp", "badge-icmp", "badge-icmp6",
        "badge-arp", "badge-ipv4", "badge-other"
    };
    static const char *const proto_bars[] = {
        "bar-tcp", "bar-udp", "bar-icmp", "bar-icmp6",
        "bar-arp", "bar-ipv4", "bar-other"
    };

    static const char *const frame_names[] = {
        "IPv4", "IPv6", "ARP", "VLAN tagged", "Unicast",
        "Multicast", "Broadcast", "Ethernet II", "IEEE 802.3",
        "Other EtherType"
    };
    static const char *const frame_badges[] = {
        "badge-ipv4", "badge-ipv6", "badge-arp", "badge-other",
        "badge-other", "badge-other", "badge-other", "badge-other",
        "badge-other", "badge-other"
    };
    static const char *const frame_bars[] = {
        "bar-ipv4", "bar-ipv6", "bar-arp", "bar-other",
        "bar-other", "bar-other", "bar-other", "bar-other",
        "bar-other", "bar-other"
    };

    GtkWidget *panels = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);

    gtk_widget_set_hexpand(panels, TRUE);
    gtk_box_append(GTK_BOX(panels),
                   make_distribution_panel(
                       "PROTOCOL DISTRIBUTION",
                       "Mutually exclusive transport and payload groups",
                       proto_names, proto_badges, proto_bars,
                       proto_rows, 7));
    gtk_box_append(GTK_BOX(panels),
                   make_distribution_panel(
                       "FRAME CHARACTERISTICS",
                       "Shares of total frames; some rows overlap",
                       frame_names, frame_badges, frame_bars,
                       frame_rows, 10));

    gtk_box_append(GTK_BOX(page), panels);

    GtkWidget *archive_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    gtk_widget_add_css_class(archive_panel, "panel");
    gtk_box_append(GTK_BOX(archive_panel),
                   make_label("CAPTURE ARCHIVE", "section-heading"));

    stats_page_archive = make_label("No capture archive available", "muted");
    gtk_box_append(GTK_BOX(archive_panel), stats_page_archive);

    gtk_box_append(GTK_BOX(page), archive_panel);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), page);

    return scroll;
}

static GtkWidget *make_settings_row(const char *title, const char *description,
                                    GtkWidget *control)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);

    gtk_widget_add_css_class(row, "setting-row");

    GtkWidget *text_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);

    gtk_widget_set_hexpand(text_box, TRUE);

    gtk_box_append(GTK_BOX(text_box), make_label(title, "setting-title"));

    GtkWidget *detail = make_label(description, "muted");
    gtk_label_set_wrap(GTK_LABEL(detail), TRUE);
    gtk_box_append(GTK_BOX(text_box), detail);

    gtk_box_append(GTK_BOX(row), text_box);
    gtk_widget_set_valign(control, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(row), control);

    return row;
}

static void sync_settings_controls(void)
{
    syncing_widgets = TRUE;

    if (settings_promisc_switch != NULL)
        gtk_switch_set_active(GTK_SWITCH(settings_promisc_switch),
                              settings.promiscuous);
    if (settings_snaplen_spin != NULL)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(settings_snaplen_spin),
                                  settings.snaplen);
    if (settings_timeout_spin != NULL)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(settings_timeout_spin),
                                  settings.timeout_ms);
    if (settings_maxrows_spin != NULL)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(settings_maxrows_spin),
                                  settings.max_rows);
    if (settings_follow_switch != NULL)
        gtk_switch_set_active(GTK_SWITCH(settings_follow_switch),
                              settings.auto_follow);
    if (settings_archive_switch != NULL)
        gtk_switch_set_active(GTK_SWITCH(settings_archive_switch),
                              settings.archive_enabled);
    if (follow_toggle != NULL)
        gtk_check_button_set_active(GTK_CHECK_BUTTON(follow_toggle),
                                    settings.auto_follow);

    syncing_widgets = FALSE;
}

static void on_settings_changed(GtkWidget *widget, gpointer user_data)
{
    (void)widget;
    (void)user_data;

    if (syncing_widgets)
        return;

    settings.promiscuous =
        gtk_switch_get_active(GTK_SWITCH(settings_promisc_switch));
    settings.snaplen =
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(settings_snaplen_spin));
    settings.timeout_ms =
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(settings_timeout_spin));
    settings.max_rows =
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(settings_maxrows_spin));
    settings.auto_follow =
        gtk_switch_get_active(GTK_SWITCH(settings_follow_switch));
    settings.archive_enabled =
        gtk_switch_get_active(GTK_SWITCH(settings_archive_switch));

    settings.snaplen = clamp_int(settings.snaplen, 64, 262144);
    settings.timeout_ms = clamp_int(settings.timeout_ms, 50, 5000);
    settings.max_rows = clamp_int(settings.max_rows, 100, 200000);

    syncing_widgets = TRUE;
    if (follow_toggle != NULL)
        gtk_check_button_set_active(GTK_CHECK_BUTTON(follow_toggle),
                                    settings.auto_follow);
    syncing_widgets = FALSE;

    trim_packet_store();
    update_counts();
    save_settings();
}

static GtkWidget *make_settings_page(void)
{
    GtkWidget *scroll = gtk_scrolled_window_new();

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER,
                                   GTK_POLICY_AUTOMATIC);

    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);

    gtk_widget_set_margin_top(page, 18);
    gtk_widget_set_margin_bottom(page, 16);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);

    gtk_box_append(GTK_BOX(page),
                   make_page_header("Settings",
                                    "Capture behaviour, display limits and "
                                    "export options are saved automatically."));

    GtkWidget *capture_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

    gtk_widget_add_css_class(capture_panel, "panel");
    gtk_box_append(GTK_BOX(capture_panel),
                   make_label("CAPTURE", "section-heading"));

    settings_promisc_switch = gtk_switch_new();
    gtk_box_append(GTK_BOX(capture_panel),
                   make_settings_row(
                       "Promiscuous mode",
                       "Capture frames not addressed to this host. "
                       "Applies to the next capture.",
                       settings_promisc_switch));

    settings_snaplen_spin = gtk_spin_button_new_with_range(64, 262144, 64);
    gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(settings_snaplen_spin), TRUE);
    gtk_box_append(GTK_BOX(capture_panel),
                   make_settings_row(
                       "Snapshot length",
                       "Maximum bytes captured per packet. Applied on Start.",
                       settings_snaplen_spin));

    settings_timeout_spin = gtk_spin_button_new_with_range(50, 5000, 50);
    gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(settings_timeout_spin), TRUE);
    gtk_box_append(GTK_BOX(capture_panel),
                   make_settings_row(
                       "Read timeout (ms)",
                       "How often the capture worker checks for Stop. "
                       "Applied on Start.",
                       settings_timeout_spin));

    gtk_box_append(GTK_BOX(page), capture_panel);

    GtkWidget *display_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

    gtk_widget_add_css_class(display_panel, "panel");
    gtk_box_append(GTK_BOX(display_panel),
                   make_label("DISPLAY", "section-heading"));

    settings_maxrows_spin = gtk_spin_button_new_with_range(100, 200000, 100);
    gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(settings_maxrows_spin), TRUE);
    gtk_box_append(GTK_BOX(display_panel),
                   make_settings_row(
                       "Maximum rows in the packet table",
                       "Older rows are dropped from the view. The PCAP "
                       "archive still keeps every packet.",
                       settings_maxrows_spin));

    settings_follow_switch = gtk_switch_new();
    gtk_box_append(GTK_BOX(display_panel),
                   make_settings_row(
                       "Follow newest packet",
                       "Automatically select and scroll to incoming packets. "
                       "Clicking an older row pauses follow.",
                       settings_follow_switch));

    gtk_box_append(GTK_BOX(page), display_panel);

    GtkWidget *export_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

    gtk_widget_add_css_class(export_panel, "panel");
    gtk_box_append(GTK_BOX(export_panel),
                   make_label("EXPORT", "section-heading"));

    settings_archive_switch = gtk_switch_new();
    gtk_box_append(GTK_BOX(export_panel),
                   make_settings_row(
                       "Keep a PCAP archive for export",
                       "Writes every captured packet to a temporary PCAP "
                       "file. Stop the capture, then use Export PCAP to "
                       "save it for Wireshark.",
                       settings_archive_switch));

    gtk_box_append(GTK_BOX(page), export_panel);

    GtkWidget *reset_button = gtk_button_new_with_label("Reset defaults");
    GtkWidget *reset_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    gtk_widget_set_halign(reset_button, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(reset_row), reset_button);
    gtk_box_append(GTK_BOX(page), reset_row);

    g_signal_connect(reset_button, "clicked",
                     G_CALLBACK(on_reset_settings_clicked), NULL);

    g_signal_connect(settings_promisc_switch, "notify::active",
                     G_CALLBACK(on_settings_changed), NULL);
    g_signal_connect(settings_snaplen_spin, "value-changed",
                     G_CALLBACK(on_settings_changed), NULL);
    g_signal_connect(settings_timeout_spin, "value-changed",
                     G_CALLBACK(on_settings_changed), NULL);
    g_signal_connect(settings_maxrows_spin, "value-changed",
                     G_CALLBACK(on_settings_changed), NULL);
    g_signal_connect(settings_follow_switch, "notify::active",
                     G_CALLBACK(on_settings_changed), NULL);
    g_signal_connect(settings_archive_switch, "notify::active",
                     G_CALLBACK(on_settings_changed), NULL);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), page);

    sync_settings_controls();

    return scroll;
}

/* ------------------------------------------------------------------------- */
/* Theme                                                                     */
/* ------------------------------------------------------------------------- */

static const char *const APP_CSS_A =
    "@define-color bg #0b0f16;"
    "@define-color surface #121824;"
    "@define-color surface_alt #161e2d;"
    "@define-color border #223047;"
    "@define-color border_soft #1a2435;"
    "@define-color text #e7edf7;"
    "@define-color muted #8798b3;"
    "@define-color accent #4da3ff;"
    "@define-color green #3ddc97;"
    "@define-color amber #f5b84b;"
    "@define-color red #ff647c;"
    "@define-color purple #b18cff;"

    "window, .background {"
    "  background-color: @bg;"
    "  color: @text;"
    "}"

    "headerbar {"
    "  background: linear-gradient(180deg, #121a28, #0e1420);"
    "  border-bottom: 1px solid @border_soft;"
    "  box-shadow: none;"
    "  min-height: 50px;"
    "}"

    "headerbar windowtitle {"
    "  font-weight: 700;"
    "}"

    ".app-title {"
    "  font-size: 15px;"
    "  font-weight: 800;"
    "  color: @text;"
    "}"

    ".app-tagline {"
    "  font-size: 11px;"
    "  color: @muted;"
    "}"

    ".sidebar {"
    "  background-color: #0d131e;"
    "  border-right: 1px solid @border_soft;"
    "  padding: 18px 12px;"
    "}"

    ".brand-mark {"
    "  min-width: 40px;"
    "  min-height: 40px;"
    "  border-radius: 11px;"
    "  background-image: linear-gradient(135deg, #2f7cf6, #50c8ff);"
    "  color: #04101f;"
    "  font-size: 20px;"
    "  font-weight: 900;"
    "}"

    ".brand-title {"
    "  font-size: 16px;"
    "  font-weight: 800;"
    "  color: @text;"
    "}"

    ".brand-subtitle {"
    "  font-size: 10px;"
    "  color: @muted;"
    "}"

    ".section-heading {"
    "  font-size: 10px;"
    "  font-weight: 800;"
    "  color: #6f819d;"
    "  margin-bottom: 2px;"
    "}"

    ".nav-button {"
    "  background: transparent;"
    "  border: 1px solid transparent;"
    "  border-radius: 9px;"
    "  padding: 10px 12px;"
    "  color: #b8c5d8;"
    "  font-weight: 600;"
    "}"

    ".nav-button:hover {"
    "  background-color: #151e2c;"
    "  color: @text;"
    "}"

    ".nav-button.nav-active {"
    "  background-image: linear-gradient(90deg, #1b3352, #16263a);"
    "  border-color: #29466b;"
    "  color: #ffffff;"
    "  box-shadow: inset 3px 0 0 @accent;"
    "}"

    ".nav-button.nav-active label {"
    "  color: #ffffff;"
    "}"

    ".status-card {"
    "  background-color: #101826;"
    "  border: 1px solid @border_soft;"
    "  border-radius: 11px;"
    "  padding: 12px;"
    "}"

    ".status-dot {"
    "  min-width: 9px;"
    "  min-height: 9px;"
    "  border-radius: 999px;"
    "  background-color: @muted;"
    "}"

    ".status-dot.status-live { background-color: @green; }"
    ".status-dot.status-idle { background-color: @muted; }"
    ".status-dot.status-error { background-color: @red; }"
    ".status-dot.status-stopping { background-color: @amber; }"
    ".status-dot.status-ok { background-color: @green; }"

    ".sidebar-status.status-live { color: @green; }"
    ".sidebar-status.status-idle { color: @muted; }"
    ".sidebar-status.status-error { color: @red; }"
    ".sidebar-status.status-stopping { color: @amber; }"
    ".sidebar-status.status-ok { color: @green; }"

    ".sidebar-status {"
    "  font-size: 10px;"
    "  font-weight: 800;"
    "  color: @muted;"
    "}"

    ".status-text {"
    "  font-size: 12px;"
    "  font-weight: 700;"
    "  color: @text;"
    "}"

    ".status-meta {"
    "  font-size: 10px;"
    "  color: @muted;"
    "}"

    ".header-status {"
    "  background-color: #121b29;"
    "  border: 1px solid @border_soft;"
    "  border-radius: 999px;"
    "  padding: 4px 12px;"
    "}"

    ".page-title {"
    "  font-size: 22px;"
    "  font-weight: 800;"
    "  color: @text;"
    "}"

    ".page-subtitle {"
    "  font-size: 12px;"
    "  color: @muted;"
    "}"

    ".toolbar-panel, .panel {"
    "  background-color: @surface;"
    "  border: 1px solid @border_soft;"
    "  border-radius: 12px;"
    "  padding: 14px;"
    "}"

    ".stat-card {"
    "  background-image: linear-gradient(160deg, #141d2c, #101724);"
    "  border: 1px solid @border_soft;"
    "  border-radius: 11px;"
    "  padding: 12px 14px;"
    "}"

    ".stat-title {"
    "  font-size: 9px;"
    "  font-weight: 800;"
    "  color: #7487a3;"
    "}"

    ".stat-value {"
    "  font-size: 21px;"
    "  font-weight: 800;"
    "  color: @text;"
    "}"

;

static const char *const APP_CSS_B =
    ".data-table {"
    "  background-color: #0f1622;"
    "  border-radius: 8px;"
    "}"

    ".data-table listview, .data-table listview > row {"
    "  background-color: transparent;"
    "}"

    ".data-table header {"
    "  background-color: #131c2a;"
    "  border-bottom: 1px solid @border_soft;"
    "}"

    ".data-table header button {"
    "  background: transparent;"
    "  border: none;"
    "  border-radius: 0;"
    "  padding: 8px 10px;"
    "  font-size: 10px;"
    "  font-weight: 800;"
    "  color: #8798b3;"
    "}"

    ".data-table header button:hover {"
    "  background-color: #1a2537;"
    "  color: @text;"
    "}"

    ".data-table row {"
    "  border-bottom: 1px solid #16202f;"
    "}"

    ".data-table row:hover {"
    "  background-color: #131c2a;"
    "}"

    ".data-table row:selected {"
    "  background-color: #183352;"
    "}"

    ".packet-cell {"
    "  font-size: 12px;"
    "  color: #d5dfec;"
    "  padding: 0 2px;"
    "}"

    ".cell-time {"
    "  font-size: 11px;"
    "  color: #93a5bf;"
    "}"

    ".cell-address {"
    "  font-size: 12px;"
    "  color: #c9d6e8;"
    "}"

    ".cell-info {"
    "  font-size: 11px;"
    "  color: #9fb0c8;"
    "}"

    ".cell-number, .cell-length {"
    "  font-size: 11px;"
    "  color: #7f91ab;"
    "}"

;

static const char *const APP_CSS_C =
    ".badge {"
    "  border-radius: 999px;"
    "  padding: 1px 8px;"
    "  font-size: 10px;"
    "  font-weight: 800;"
    "  background-color: #1d2939;"
    "  color: #b6c4d8;"
    "}"

    ".badge-tcp { background-color: #123a52; color: #68c8ff; }"
    ".badge-udp { background-color: #2a2350; color: #b7a4ff; }"
    ".badge-icmp { background-color: #173b2f; color: #5fe0a1; }"
    ".badge-icmp6 { background-color: #123c3d; color: #5ddbd7; }"
    ".badge-arp { background-color: #423117; color: #f6c66b; }"
    ".badge-ipv4 { background-color: #1b2f50; color: #7fb4ff; }"
    ".badge-ipv6 { background-color: #2b2247; color: #c2a4ff; }"
    ".badge-other { background-color: #2a3241; color: #9fb0c5; }"

    ".card-label .badge { margin-right: 8px; }"

    ".pill-button {"
    "  border-radius: 999px;"
    "  padding: 5px 13px;"
    "  font-size: 11px;"
    "  font-weight: 600;"
    "}"

    ".details-view, .details-view text {"
    "  background-color: #0b111b;"
    "  color: #c8d5e7;"
    "  font-family: monospace;"
    "  font-size: 12px;"
    "}"

    ".empty-state {"
    "  padding: 28px;"
    "}"

    ".empty-symbol {"
    "  font-size: 40px;"
    "  color: #34445c;"
    "}"

    ".empty-title {"
    "  font-size: 15px;"
    "  font-weight: 700;"
    "  color: #8fa1ba;"
    "}"

    ".muted {"
    "  font-size: 11px;"
    "  color: @muted;"
    "}"

    ".banner {"
    "  background: transparent;"
    "  border: none;"
    "}"

    ".banner-content {"
    "  padding: 9px 12px;"
    "  border-radius: 9px;"
    "  border: 1px solid @border;"
    "}"

    ".banner-info .banner-content {"
    "  background-color: #15243a; border-color: #27476f;"
    "}"
    ".banner-success .banner-content {"
    "  background-color: #102a22; border-color: #225a45;"
    "}"
    ".banner-warning .banner-content {"
    "  background-color: #2e2512; border-color: #66501e;"
    "}"
    ".banner-error .banner-content {"
    "  background-color: #301620; border-color: #6e2a3c;"
    "}"

    ".banner label {"
    "  font-size: 12px;"
    "}"

    ".banner-close {"
    "  font-size: 11px;"
    "  font-weight: 600;"
    "}"

    ".dist-value {"
    "  font-size: 12px;"
    "  font-weight: 700;"
    "  color: #cddaeb;"
    "}"

    ".dist-bar {"
    "  min-height: 8px;"
    "}"

    ".dist-bar trough {"
    "  background-color: #1a2434;"
    "  border-radius: 999px;"
    "  min-height: 8px;"
    "  border: none;"
    "}"

    ".dist-bar progress {"
    "  border-radius: 999px;"
    "  min-height: 8px;"
    "  background-color: #3d78c8;"
    "}"

    ".bar-tcp progress { background-color: #3d9fdb; }"
    ".bar-udp progress { background-color: #8b73e8; }"
    ".bar-icmp progress { background-color: #38b87e; }"
    ".bar-icmp6 progress { background-color: #35b9b5; }"
    ".bar-arp progress { background-color: #d9a544; }"
    ".bar-ipv4 progress { background-color: #4d8fe6; }"
    ".bar-ipv6 progress { background-color: #9a7bea; }"
    ".bar-other progress { background-color: #596a80; }"

    ".setting-row {"
    "  padding: 11px 4px;"
    "  border-bottom: 1px solid #182233;"
    "}"

    ".setting-row:last-child {"
    "  border-bottom: none;"
    "}"

    ".setting-title {"
    "  font-size: 13px;"
    "  font-weight: 600;"
    "  color: #dbe5f2;"
    "}"

    ".setting-row .muted {"
    "  font-size: 11px;"
    "}"

    "spinbutton, entry, dropdown button {"
    "  background-color: #0d1420;"
    "  border: 1px solid @border;"
    "  border-radius: 7px;"
    "  color: @text;"
    "  min-height: 30px;"
    "}"

    "entry:focus, spinbutton:focus, dropdown button:focus {"
    "  border-color: @accent;"
    "  box-shadow: 0 0 0 1px alpha(@accent, 0.35);"
    "}"

    "switch {"
    "  background-color: #263244;"
    "}"

    "switch:checked {"
    "  background-color: #2f7cf6;"
    "}"

    "checkbutton {"
    "  font-size: 11px;"
    "  color: #a9b8cd;"
    "}"

    "scrollbar {"
    "  background-color: transparent;"
    "}"

    "scrollbar slider {"
    "  background-color: #2b3a50;"
    "  border-radius: 999px;"
    "  min-width: 7px;"
    "  min-height: 7px;"
    "}"

    "scrollbar slider:hover {"
    "  background-color: #3a4d68;"
    "}"

    "tooltip {"
    "  background-color: #1b2534;"
    "  color: @text;"
    "  border: 1px solid @border;"
    "  border-radius: 6px;"
    "}"

    "menubutton > button {"
    "  background-color: #0d1420;"
    "  border: 1px solid @border;"
    "  border-radius: 7px;"
    "}"

    "popover > contents {"
    "  background-color: #121a28;"
    "  border: 1px solid @border;"
    "  border-radius: 8px;"
    "}"

    "alertdialog {"
    "  background-color: @surface;"
    "}"

    "separator {"
    "  background-color: @border_soft;"
    "}"

    ".nav-separator {"
    "  background-color: #1a2333;"
    "  min-height: 1px;"
    "  margin: 8px 2px;"
    "}"

    ".suggested-action {"
    "  background-image: linear-gradient(180deg, #2f8df7, #2470d8);"
    "  border: 1px solid #3d95f8;"
    "  color: #ffffff;"
    "  font-weight: 700;"
    "}"

    ".destructive-action {"
    "  background-image: linear-gradient(180deg, #e2576d, #c53d54);"
    "  border: 1px solid #ef6c81;"
    "  color: #ffffff;"
    "  font-weight: 700;"
    "}"

    ".suggested-action:disabled, .destructive-action:disabled,"
    ".pill-button:disabled {"
    "  opacity: 0.45;"
    "}";

static void install_css(void)
{
    GtkCssProvider *provider = gtk_css_provider_new();
    GdkDisplay *display = gdk_display_get_default();

    char *css = g_strconcat(APP_CSS_A, APP_CSS_B, APP_CSS_C, NULL);

    gtk_css_provider_load_from_string(provider, css);
    g_free(css);

    if (display != NULL)
        gtk_style_context_add_provider_for_display(
            display, GTK_STYLE_PROVIDER(provider),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    g_object_unref(provider);
}

/* ------------------------------------------------------------------------- */
/* Shell                                                                     */
/* ------------------------------------------------------------------------- */

static GtkWidget *main_stack;
static gint active_page_index;

static void set_active_page(gint index)
{
    static const char *const page_names[] = {
        "live", "history", "statistics", "settings"
    };

    if (index < 0 || index >= (gint)G_N_ELEMENTS(page_names))
        return;

    active_page_index = index;
    gtk_stack_set_visible_child_name(GTK_STACK(main_stack), page_names[index]);

    for (size_t i = 0; i < G_N_ELEMENTS(nav_buttons); i++)
    {
        if (nav_buttons[i] == NULL)
            continue;

        if ((gint)i == index)
            gtk_widget_add_css_class(nav_buttons[i], "nav-active");
        else
            gtk_widget_remove_css_class(nav_buttons[i], "nav-active");
    }
}

static void on_nav_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;

    set_active_page(GPOINTER_TO_INT(user_data));
}

static GtkWidget *add_nav_button(GtkBox *sidebar, const char *icon_name,
                                 const char *text, gint index)
{
    GtkWidget *button = gtk_button_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *icon = gtk_image_new_from_icon_name(icon_name);
    GtkWidget *label = gtk_label_new(text);

    gtk_widget_set_halign(content, GTK_ALIGN_FILL);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_widget_set_hexpand(label, TRUE);

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 16);
    gtk_widget_add_css_class(button, "nav-button");
    gtk_box_append(GTK_BOX(content), icon);
    gtk_box_append(GTK_BOX(content), label);
    gtk_button_set_child(GTK_BUTTON(button), content);

    g_signal_connect(button, "clicked", G_CALLBACK(on_nav_clicked),
                     GINT_TO_POINTER(index));

    gtk_box_append(sidebar, button);
    nav_buttons[index] = button;

    return button;
}

static GtkWidget *make_sidebar(void)
{
    GtkWidget *sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);

    gtk_widget_add_css_class(sidebar, "sidebar");
    gtk_widget_set_size_request(sidebar, 226, -1);

    GtkWidget *brand = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *mark = make_label("F", "brand-mark");
    GtkWidget *brand_text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    gtk_label_set_xalign(GTK_LABEL(mark), 0.5f);
    gtk_label_set_yalign(GTK_LABEL(mark), 0.5f);
    gtk_box_append(GTK_BOX(brand_text), make_label("FrameScope",
                                                   "brand-title"));
    gtk_box_append(GTK_BOX(brand_text),
                   make_label("NETWORK ANALYZER", "brand-subtitle"));
    gtk_box_append(GTK_BOX(brand), mark);
    gtk_box_append(GTK_BOX(brand), brand_text);

    gtk_box_append(GTK_BOX(sidebar), brand);

    GtkWidget *nav = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

    gtk_box_append(GTK_BOX(nav),
                   make_label("WORKSPACE", "section-heading"));
    add_nav_button(GTK_BOX(nav), "media-record-symbolic",
                   "Live Capture", 0);
    add_nav_button(GTK_BOX(nav), "document-open-recent-symbolic",
                   "Packet History", 1);
    add_nav_button(GTK_BOX(nav), "utilities-system-monitor-symbolic",
                   "Statistics", 2);
    add_nav_button(GTK_BOX(nav), "emblem-system-symbolic",
                   "Settings", 3);

    gtk_box_append(GTK_BOX(sidebar), nav);

    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_vexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(sidebar), spacer);

    GtkWidget *status_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

    gtk_widget_add_css_class(status_card, "status-card");
    gtk_box_append(GTK_BOX(status_card),
                   make_label("CAPTURE ENGINE", "section-heading"));

    GtkWidget *status_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    sidebar_dot = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    sidebar_status = make_label("READY", "sidebar-status");
    gtk_widget_add_css_class(sidebar_dot, "status-dot");
    gtk_widget_set_size_request(sidebar_dot, 8, 8);
    gtk_widget_set_hexpand(sidebar_dot, FALSE);
    gtk_widget_set_valign(sidebar_dot, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(status_row), sidebar_dot);
    gtk_box_append(GTK_BOX(status_row), sidebar_status);
    gtk_box_append(GTK_BOX(status_card), status_row);

    status_meta = make_label("libpcap · Ethernet (DLT_EN10MB)",
                             "status-meta");
    gtk_label_set_wrap(GTK_LABEL(status_meta), TRUE);
    gtk_label_set_lines(GTK_LABEL(status_meta), 4);
    gtk_box_append(GTK_BOX(status_card), status_meta);

    gtk_box_append(GTK_BOX(sidebar), status_card);

    return sidebar;
}

static GtkWidget *make_headerbar(void)
{
    GtkWidget *header = gtk_header_bar_new();

    GtkWidget *title_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    GtkWidget *text_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    gtk_box_append(GTK_BOX(text_box), make_label("FrameScope", "app-title"));
    gtk_box_append(GTK_BOX(text_box),
                   make_label("Packet analysis for the desktop",
                              "app-tagline"));
    gtk_box_append(GTK_BOX(title_box), text_box);

    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header), title_box);
    gtk_header_bar_set_show_title_buttons(GTK_HEADER_BAR(header), TRUE);

    GtkWidget *status_pill = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

    gtk_widget_add_css_class(status_pill, "header-status");

    status_dot = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    status_label = make_label("Ready", "status-text");

    gtk_widget_add_css_class(status_dot, "status-dot");
    gtk_widget_set_size_request(status_dot, 9, 9);
    gtk_widget_set_hexpand(status_dot, FALSE);
    gtk_widget_set_valign(status_dot, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(status_pill), status_dot);
    gtk_box_append(GTK_BOX(status_pill), status_label);

    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), status_pill);

    return header;
}

static void on_reset_settings_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    settings_set_defaults(&settings);

    sync_settings_controls();
    trim_packet_store();
    update_counts();
    save_settings();
    show_banner("Settings restored to defaults.", BANNER_INFO);
}

/* ------------------------------------------------------------------------- */
/* Actions and activation                                                    */
/* ------------------------------------------------------------------------- */

static gboolean history_matches(gpointer item, gpointer user_data)
{
    (void)user_data;

    if (history_needle == NULL || history_needle[0] == '\0')
        return TRUE;

    PacketRecord *record = item;

    return record != NULL && strstr(record->search, history_needle) != NULL;
}

static void on_action_start_stop(GSimpleAction *action, GVariant *parameter,
                                 gpointer user_data)
{
    (void)action;
    (void)parameter;
    (void)user_data;

    if (capture_running)
        on_stop_clicked(NULL, NULL);
    else
        on_start_clicked(NULL, NULL);
}

static void on_action_export(GSimpleAction *action, GVariant *parameter,
                             gpointer user_data)
{
    (void)action;
    (void)parameter;
    (void)user_data;

    on_export_clicked(NULL, NULL);
}

static void on_action_clear(GSimpleAction *action, GVariant *parameter,
                            gpointer user_data)
{
    (void)action;
    (void)parameter;
    (void)user_data;

    on_clear_clicked(NULL, NULL);
}

static void on_action_history_search(GSimpleAction *action,
                                     GVariant *parameter, gpointer user_data)
{
    (void)action;
    (void)parameter;
    (void)user_data;

    set_active_page(1);

    if (history_search != NULL)
        gtk_widget_grab_focus(history_search);
}

static void on_action_refresh(GSimpleAction *action, GVariant *parameter,
                              gpointer user_data)
{
    (void)action;
    (void)parameter;
    (void)user_data;

    if (capture_running)
        return;

    set_active_page(0);
    load_interfaces();
}

static void on_action_page(GSimpleAction *action, GVariant *parameter,
                           gpointer user_data)
{
    (void)action;
    (void)user_data;

    if (parameter != NULL)
        set_active_page(g_variant_get_int32(parameter));
}

static void on_action_quit(GSimpleAction *action, GVariant *parameter,
                           gpointer user_data)
{
    (void)action;
    (void)parameter;
    (void)user_data;

    if (window != NULL)
        gtk_window_close(GTK_WINDOW(window));
}

static const GActionEntry app_actions[] = {
    {"start-stop", on_action_start_stop, NULL, NULL, NULL, {0, 0, 0}},
    {"export", on_action_export, NULL, NULL, NULL, {0, 0, 0}},
    {"clear", on_action_clear, NULL, NULL, NULL, {0, 0, 0}},
    {"history-search", on_action_history_search, NULL, NULL, NULL,
     {0, 0, 0}},
    {"refresh", on_action_refresh, NULL, NULL, NULL, {0, 0, 0}},
    {"page", on_action_page, "i", NULL, NULL, {0, 0, 0}},
    {"quit", on_action_quit, NULL, NULL, NULL, {0, 0, 0}}
};

static void install_actions(GtkApplication *app)
{
    g_action_map_add_action_entries(G_ACTION_MAP(app), app_actions,
                                    G_N_ELEMENTS(app_actions), app);

    gtk_application_set_accels_for_action(app, "app.start-stop",
                                          (const char *[]){"<Control>s", NULL});
    gtk_application_set_accels_for_action(app, "app.export",
                                          (const char *[]){"<Control>e", NULL});
    gtk_application_set_accels_for_action(app, "app.clear",
                                          (const char *[]){"<Control>k", NULL});
    gtk_application_set_accels_for_action(app, "app.history-search",
                                          (const char *[]){"<Control>f", NULL});
    gtk_application_set_accels_for_action(app, "app.refresh",
                                          (const char *[]){"F5", NULL});
    gtk_application_set_accels_for_action(app, "app.page(0)",
                                          (const char *[]){"<Control>1", NULL});
    gtk_application_set_accels_for_action(app, "app.page(1)",
                                          (const char *[]){"<Control>2", NULL});
    gtk_application_set_accels_for_action(app, "app.page(2)",
                                          (const char *[]){"<Control>3", NULL});
    gtk_application_set_accels_for_action(app, "app.page(3)",
                                          (const char *[]){"<Control>4", NULL});
    gtk_application_set_accels_for_action(app, "app.quit",
                                          (const char *[]){"<Control>q", NULL});
}

static void on_activate(GtkApplication *app, gpointer user_data)
{
    (void)user_data;

    if (window != NULL)
    {
        gtk_window_present(GTK_WINDOW(window));
        return;
    }

    GtkSettings *gtk_settings = gtk_settings_get_default();

    if (gtk_settings != NULL)
    {
        g_object_set(gtk_settings,
                     "gtk-application-prefer-dark-theme", TRUE,
                     "gtk-theme-name", "Adwaita",
                     NULL);
    }

    install_css();
    load_settings();

    packet_store = g_list_store_new(packet_record_get_type());

    live_selection = gtk_single_selection_new(G_LIST_MODEL(packet_store));
    gtk_single_selection_set_autoselect(GTK_SINGLE_SELECTION(live_selection),
                                        FALSE);
    gtk_single_selection_set_can_unselect(
        GTK_SINGLE_SELECTION(live_selection), TRUE);

    history_filter = GTK_FILTER(gtk_custom_filter_new(history_matches,
                                                      NULL, NULL));
    history_filter_model = gtk_filter_list_model_new(
        G_LIST_MODEL(packet_store), g_object_ref(history_filter));

    history_selection = gtk_single_selection_new(
        G_LIST_MODEL(history_filter_model));
    gtk_single_selection_set_autoselect(
        GTK_SINGLE_SELECTION(history_selection), FALSE);
    gtk_single_selection_set_can_unselect(
        GTK_SINGLE_SELECTION(history_selection), TRUE);

    packet_queue = g_async_queue_new();

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), APP_NAME);
    gtk_window_set_default_size(GTK_WINDOW(window),
                                settings.window_width,
                                settings.window_height);
    gtk_window_set_titlebar(GTK_WINDOW(window), make_headerbar());
    gtk_window_set_hide_on_close(GTK_WINDOW(window), FALSE);

    GtkWidget *shell = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    gtk_box_append(GTK_BOX(shell), make_sidebar());

    main_stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(main_stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_set_transition_duration(GTK_STACK(main_stack), 120);
    gtk_widget_set_hexpand(main_stack, TRUE);
    gtk_widget_set_vexpand(main_stack, TRUE);

    gtk_stack_add_named(GTK_STACK(main_stack), make_live_page(), "live");
    gtk_stack_add_named(GTK_STACK(main_stack),
                        make_history_page(), "history");
    gtk_stack_add_named(GTK_STACK(main_stack),
                        make_statistics_page(), "statistics");
    gtk_stack_add_named(GTK_STACK(main_stack),
                        make_settings_page(), "settings");

    gtk_box_append(GTK_BOX(shell), main_stack);
    gtk_window_set_child(GTK_WINDOW(window), shell);

    g_signal_connect(window, "close-request",
                     G_CALLBACK(on_close_request), NULL);

    set_active_page(0);

    load_interfaces();
    sync_settings_controls();
    apply_follow_setting(settings.auto_follow, FALSE);
    refresh_data_ui();

    gtk_window_present(GTK_WINDOW(window));
}

int main(int argc, char **argv)
{
    GtkApplication *app = gtk_application_new(APP_ID,
                                              G_APPLICATION_DEFAULT_FLAGS);

    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);

    install_actions(app);

    int status = g_application_run(G_APPLICATION(app), argc, argv);

    g_object_unref(app);

    return status;
}
