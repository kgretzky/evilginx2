package tgbotapi

import (
	"encoding/json"
	"io"
	"net/url"
	"strconv"
)

// Telegram constants
const (
	// APIEndpoint is the endpoint for all API methods,
	// with formatting for Sprintf.
	APIEndpoint = "https://api.telegram.org/bot%s/%s"
	// FileEndpoint is the endpoint for downloading a file from Telegram.
	FileEndpoint = "https://api.telegram.org/file/bot%s/%s"
)

// Constant values for ChatActions
const (
	ChatTyping         = "typing"
	ChatUploadPhoto    = "upload_photo"
	ChatRecordVideo    = "record_video"
	ChatUploadVideo    = "upload_video"
	ChatRecordAudio    = "record_audio"
	ChatUploadAudio    = "upload_audio"
	ChatUploadDocument = "upload_document"
	ChatFindLocation   = "find_location"
)

// API errors
const (
	// ErrAPIForbidden happens when a token is bad
	ErrAPIForbidden = "forbidden"
)

// Constant values for ParseMode in MessageConfig
const (
	ModeMarkdown = "Markdown"
	ModeHTML     = "HTML"
)

// Library errors
const (
	// ErrBadFileType happens when you pass an unknown type
	ErrBadFileType = "bad file type"
	ErrBadURL      = "bad or empty url"
)

// Chattable is any config type that can be sent.
type Chattable interface {
	values() (url.Values, error)
	method() string
}

// Fileable is any config type that can be sent that includes a file.
type Fileable interface {
	Chattable
	params() (map[string]string, error)
	name() string
	getFile() interface{}
	useExistingFile() bool
}

// BaseChat is base type for all chat config types.
type BaseChat struct {
	ChatID              int64 // required
	ChannelUsername     string
	ReplyToMessageID    int
	ReplyMarkup         interface{}
	DisableNotification bool
}

// values returns url.Values representation of BaseChat
func (chat *BaseChat) values() (url.Values, error) {
	v := url.Values{}
	if chat.ChannelUsername != "" {
		v.Add("chat_id", chat.ChannelUsername)
	} else {
		v.Add("chat_id", strconv.FormatInt(chat.ChatID, 10))
	}

	if chat.ReplyToMessageID != 0 {
		v.Add("reply_to_message_id", strconv.Itoa(chat.ReplyToMessageID))
	}

	if chat.ReplyMarkup != nil {
		data, err := json.Marshal(chat.ReplyMarkup)
		if err != nil {
			return v, err
		}

		v.Add("reply_markup", string(data))
	}

	v.Add("disable_notification", strconv.FormatBool(chat.DisableNotification))

	return v, nil
}

// BaseFile is a base type for all file config types.
type BaseFile struct {
	BaseChat
	File        interface{}
	FileID      string
	UseExisting bool
	MimeType    string
	FileSize    int
}

// params returns a map[string]string representation of BaseFile.
func (file BaseFile) params() (map[string]string, error) {
	params := make(map[string]string)

	if file.ChannelUsername != "" {
		params["chat_id"] = file.ChannelUsername
	} else {
		params["chat_id"] = strconv.FormatInt(file.ChatID, 10)
	}

	if file.ReplyToMessageID != 0 {
		params["reply_to_message_id"] = strconv.Itoa(file.ReplyToMessageID)
	}

	if file.ReplyMarkup != nil {
		data, err := json.Marshal(file.ReplyMarkup)
		if err != nil {
			return params, err
		}

		params["reply_markup"] = string(data)
	}

	if file.MimeType != "" {
		params["mime_type"] = file.MimeType
	}

	if file.FileSize > 0 {
		params["file_size"] = strconv.Itoa(file.FileSize)
	}

	params["disable_notification"] = strconv.FormatBool(file.DisableNotification)

	return params, nil
}

// getFile returns the file.
func (file BaseFile) getFile() interface{} {
	return file.File
}

// useExistingFile returns if the BaseFile has already been uploaded.
func (file BaseFile) useExistingFile() bool {
	return file.UseExisting
}

// BaseEdit is base type of all chat edits.
type BaseEdit struct {
	ChatID          int64
	ChannelUsername string
	MessageID       int
	InlineMessageID string
	ReplyMarkup     *InlineKeyboardMarkup
}

func (edit BaseEdit) values() (url.Values, error) {
	v := url.Values{}

	if edit.InlineMessageID == "" {
		if edit.ChannelUsername != "" {
			v.Add("chat_id", edit.ChannelUsername)
		} else {
			v.Add("chat_id", strconv.FormatInt(edit.ChatID, 10))
		}
		v.Add("message_id", strconv.Itoa(edit.MessageID))
	} else {
		v.Add("inline_message_id", edit.InlineMessageID)
	}

	if edit.ReplyMarkup != nil {
		data, err := json.Marshal(edit.ReplyMarkup)
		if err != nil {
			return v, err
		}
		v.Add("reply_markup", string(data))
	}

	return v, nil
}

// MessageConfig contains information about a SendMessage request.
type MessageConfig struct {
	BaseChat
	Text                  string
	ParseMode             string
	DisableWebPagePreview bool
}

// values returns a url.Values representation of MessageConfig.
func (config MessageConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}
	v.Add("text", config.Text)
	v.Add("disable_web_page_preview", strconv.FormatBool(config.DisableWebPagePreview))
	if config.ParseMode != "" {
		v.Add("parse_mode", config.ParseMode)
	}

	return v, nil
}

// method returns Telegram API method name for sending Message.
func (config MessageConfig) method() string {
	return "sendMessage"
}

// ForwardConfig contains information about a ForwardMessage request.
type ForwardConfig struct {
	BaseChat
	FromChatID          int64 // required
	FromChannelUsername string
	MessageID           int // required
}

// values returns a url.Values representation of ForwardConfig.
func (config ForwardConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}
	v.Add("from_chat_id", strconv.FormatInt(config.FromChatID, 10))
	v.Add("message_id", strconv.Itoa(config.MessageID))
	return v, nil
}

// method returns Telegram API method name for sending Forward.
func (config ForwardConfig) method() string {
	return "forwardMessage"
}

// PhotoConfig contains information about a SendPhoto request.
type PhotoConfig struct {
	BaseFile
	Caption   string
	ParseMode string
}

// Params returns a map[string]string representation of PhotoConfig.
func (config PhotoConfig) params() (map[string]string, error) {
	params, _ := config.BaseFile.params()

	if config.Caption != "" {
		params["caption"] = config.Caption
		if config.ParseMode != "" {
			params["parse_mode"] = config.ParseMode
		}
	}

	return params, nil
}

// Values returns a url.Values representation of PhotoConfig.
func (config PhotoConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add(config.name(), config.FileID)
	if config.Caption != "" {
		v.Add("caption", config.Caption)
		if config.ParseMode != "" {
			v.Add("parse_mode", config.ParseMode)
		}
	}

	return v, nil
}

// name returns the field name for the Photo.
func (config PhotoConfig) name() string {
	return "photo"
}

// method returns Telegram API method name for sending Photo.
func (config PhotoConfig) method() string {
	return "sendPhoto"
}

// AudioConfig contains information about a SendAudio request.
type AudioConfig struct {
	BaseFile
	Caption   string
	ParseMode string
	Duration  int
	Performer string
	Title     string
}

// values returns a url.Values representation of AudioConfig.
func (config AudioConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add(config.name(), config.FileID)
	if config.Duration != 0 {
		v.Add("duration", strconv.Itoa(config.Duration))
	}

	if config.Performer != "" {
		v.Add("performer", config.Performer)
	}
	if config.Title != "" {
		v.Add("title", config.Title)
	}
	if config.Caption != "" {
		v.Add("caption", config.Caption)
		if config.ParseMode != "" {
			v.Add("parse_mode", config.ParseMode)
		}
	}

	return v, nil
}

// params returns a map[string]string representation of AudioConfig.
func (config AudioConfig) params() (map[string]string, error) {
	params, _ := config.BaseFile.params()

	if config.Duration != 0 {
		params["duration"] = strconv.Itoa(config.Duration)
	}

	if config.Performer != "" {
		params["performer"] = config.Performer
	}
	if config.Title != "" {
		params["title"] = config.Title
	}
	if config.Caption != "" {
		params["caption"] = config.Caption
		if config.ParseMode != "" {
			params["parse_mode"] = config.ParseMode
		}
	}

	return params, nil
}

// name returns the field name for the Audio.
func (config AudioConfig) name() string {
	return "audio"
}

// method returns Telegram API method name for sending Audio.
func (config AudioConfig) method() string {
	return "sendAudio"
}

// DocumentConfig contains information about a SendDocument request.
type DocumentConfig struct {
	BaseFile
	Caption   string
	ParseMode string
}

// values returns a url.Values representation of DocumentConfig.
func (config DocumentConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add(config.name(), config.FileID)
	if config.Caption != "" {
		v.Add("caption", config.Caption)
		if config.ParseMode != "" {
			v.Add("parse_mode", config.ParseMode)
		}
	}

	return v, nil
}

// params returns a map[string]string representation of DocumentConfig.
func (config DocumentConfig) params() (map[string]string, error) {
	params, _ := config.BaseFile.params()

	if config.Caption != "" {
		params["caption"] = config.Caption
		if config.ParseMode != "" {
			params["parse_mode"] = config.ParseMode
		}
	}

	return params, nil
}

// name returns the field name for the Document.
func (config DocumentConfig) name() string {
	return "document"
}

// method returns Telegram API method name for sending Document.
func (config DocumentConfig) method() string {
	return "sendDocument"
}

// StickerConfig contains information about a SendSticker request.
type StickerConfig struct {
	BaseFile
}

// values returns a url.Values representation of StickerConfig.
func (config StickerConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add(config.name(), config.FileID)

	return v, nil
}

// params returns a map[string]string representation of StickerConfig.
func (config StickerConfig) params() (map[string]string, error) {
	params, _ := config.BaseFile.params()

	return params, nil
}

// name returns the field name for the Sticker.
func (config StickerConfig) name() string {
	return "sticker"
}

// method returns Telegram API method name for sending Sticker.
func (config StickerConfig) method() string {
	return "sendSticker"
}

// VideoConfig contains information about a SendVideo request.
type VideoConfig struct {
	BaseFile
	Duration  int
	Caption   string
	ParseMode string
}

// values returns a url.Values representation of VideoConfig.
func (config VideoConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add(config.name(), config.FileID)
	if config.Duration != 0 {
		v.Add("duration", strconv.Itoa(config.Duration))
	}
	if config.Caption != "" {
		v.Add("caption", config.Caption)
		if config.ParseMode != "" {
			v.Add("parse_mode", config.ParseMode)
		}
	}

	return v, nil
}

// params returns a map[string]string representation of VideoConfig.
func (config VideoConfig) params() (map[string]string, error) {
	params, _ := config.BaseFile.params()

	if config.Caption != "" {
		params["caption"] = config.Caption
		if config.ParseMode != "" {
			params["parse_mode"] = config.ParseMode
		}
	}

	return params, nil
}

// name returns the field name for the Video.
func (config VideoConfig) name() string {
	return "video"
}

// method returns Telegram API method name for sending Video.
func (config VideoConfig) method() string {
	return "sendVideo"
}

// AnimationConfig contains information about a SendAnimation request.
type AnimationConfig struct {
	BaseFile
	Duration  int
	Caption   string
	ParseMode string
}

// values returns a url.Values representation of AnimationConfig.
func (config AnimationConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add(config.name(), config.FileID)
	if config.Duration != 0 {
		v.Add("duration", strconv.Itoa(config.Duration))
	}
	if config.Caption != "" {
		v.Add("caption", config.Caption)
		if config.ParseMode != "" {
			v.Add("parse_mode", config.ParseMode)
		}
	}

	return v, nil
}

// params returns a map[string]string representation of AnimationConfig.
func (config AnimationConfig) params() (map[string]string, error) {
	params, _ := config.BaseFile.params()

	if config.Caption != "" {
		params["caption"] = config.Caption
		if config.ParseMode != "" {
			params["parse_mode"] = config.ParseMode
		}
	}

	return params, nil
}

// name returns the field name for the Animation.
func (config AnimationConfig) name() string {
	return "animation"
}

// method returns Telegram API method name for sending Animation.
func (config AnimationConfig) method() string {
	return "sendAnimation"
}

// VideoNoteConfig contains information about a SendVideoNote request.
type VideoNoteConfig struct {
	BaseFile
	Duration int
	Length   int
}

// values returns a url.Values representation of VideoNoteConfig.
func (config VideoNoteConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add(config.name(), config.FileID)
	if config.Duration != 0 {
		v.Add("duration", strconv.Itoa(config.Duration))
	}

	// Telegram API seems to have a bug, if no length is provided or it is 0, it will send an error response
	if config.Length != 0 {
		v.Add("length", strconv.Itoa(config.Length))
	}

	return v, nil
}

// params returns a map[string]string representation of VideoNoteConfig.
func (config VideoNoteConfig) params() (map[string]string, error) {
	params, _ := config.BaseFile.params()

	if config.Length != 0 {
		params["length"] = strconv.Itoa(config.Length)
	}
	if config.Duration != 0 {
		params["duration"] = strconv.Itoa(config.Duration)
	}

	return params, nil
}

// name returns the field name for the VideoNote.
func (config VideoNoteConfig) name() string {
	return "video_note"
}

// method returns Telegram API method name for sending VideoNote.
func (config VideoNoteConfig) method() string {
	return "sendVideoNote"
}

// VoiceConfig contains information about a SendVoice request.
type VoiceConfig struct {
	BaseFile
	Caption   string
	ParseMode string
	Duration  int
}

// values returns a url.Values representation of VoiceConfig.
func (config VoiceConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add(config.name(), config.FileID)
	if config.Duration != 0 {
		v.Add("duration", strconv.Itoa(config.Duration))
	}
	if config.Caption != "" {
		v.Add("caption", config.Caption)
		if config.ParseMode != "" {
			v.Add("parse_mode", config.ParseMode)
		}
	}

	return v, nil
}

// params returns a map[string]string representation of VoiceConfig.
func (config VoiceConfig) params() (map[string]string, error) {
	params, _ := config.BaseFile.params()

	if config.Duration != 0 {
		params["duration"] = strconv.Itoa(config.Duration)
	}
	if config.Caption != "" {
		params["caption"] = config.Caption
		if config.ParseMode != "" {
			params["parse_mode"] = config.ParseMode
		}
	}

	return params, nil
}

// name returns the field name for the Voice.
func (config VoiceConfig) name() string {
	return "voice"
}

// method returns Telegram API method name for sending Voice.
func (config VoiceConfig) method() string {
	return "sendVoice"
}

// MediaGroupConfig contains information about a sendMediaGroup request.
type MediaGroupConfig struct {
	BaseChat
	InputMedia []interface{}
}

func (config MediaGroupConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	data, err := json.Marshal(config.InputMedia)
	if err != nil {
		return v, err
	}

	v.Add("media", string(data))

	return v, nil
}

func (config MediaGroupConfig) method() string {
	return "sendMediaGroup"
}

// LocationConfig contains information about a SendLocation request.
type LocationConfig struct {
	BaseChat
	Latitude  float64 // required
	Longitude float64 // required
}

// values returns a url.Values representation of LocationConfig.
func (config LocationConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add("latitude", strconv.FormatFloat(config.Latitude, 'f', 6, 64))
	v.Add("longitude", strconv.FormatFloat(config.Longitude, 'f', 6, 64))

	return v, nil
}

// method returns Telegram API method name for sending Location.
func (config LocationConfig) method() string {
	return "sendLocation"
}

// VenueConfig contains information about a SendVenue request.
type VenueConfig struct {
	BaseChat
	Latitude     float64 // required
	Longitude    float64 // required
	Title        string  // required
	Address      string  // required
	FoursquareID string
}

func (config VenueConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add("latitude", strconv.FormatFloat(config.Latitude, 'f', 6, 64))
	v.Add("longitude", strconv.FormatFloat(config.Longitude, 'f', 6, 64))
	v.Add("title", config.Title)
	v.Add("address", config.Address)
	if config.FoursquareID != "" {
		v.Add("foursquare_id", config.FoursquareID)
	}

	return v, nil
}

func (config VenueConfig) method() string {
	return "sendVenue"
}

// ContactConfig allows you to send a contact.
type ContactConfig struct {
	BaseChat
	PhoneNumber string
	FirstName   string
	LastName    string
}

func (config ContactConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add("phone_number", config.PhoneNumber)
	v.Add("first_name", config.FirstName)
	v.Add("last_name", config.LastName)

	return v, nil
}

func (config ContactConfig) method() string {
	return "sendContact"
}

// GameConfig allows you to send a game.
type GameConfig struct {
	BaseChat
	GameShortName string
}

func (config GameConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}

	v.Add("game_short_name", config.GameShortName)

	return v, nil
}

func (config GameConfig) method() string {
	return "sendGame"
}

// SetGameScoreConfig allows you to update the game score in a chat.
type SetGameScoreConfig struct {
	UserID             int
	Score              int
	Force              bool
	DisableEditMessage bool
	ChatID             int64
	ChannelUsername    string
	MessageID          int
	InlineMessageID    string
}

func (config SetGameScoreConfig) values() (url.Values, error) {
	v := url.Values{}

	v.Add("user_id", strconv.Itoa(config.UserID))
	v.Add("score", strconv.Itoa(config.Score))
	if config.InlineMessageID == "" {
		if config.ChannelUsername == "" {
			v.Add("chat_id", strconv.FormatInt(config.ChatID, 10))
		} else {
			v.Add("chat_id", config.ChannelUsername)
		}
		v.Add("message_id", strconv.Itoa(config.MessageID))
	} else {
		v.Add("inline_message_id", config.InlineMessageID)
	}
	v.Add("disable_edit_message", strconv.FormatBool(config.DisableEditMessage))

	return v, nil
}

func (config SetGameScoreConfig) method() string {
	return "setGameScore"
}

// GetGameHighScoresConfig allows you to fetch the high scores for a game.
type GetGameHighScoresConfig struct {
	UserID          int
	ChatID          int
	ChannelUsername string
	MessageID       int
	InlineMessageID string
}

func (config GetGameHighScoresConfig) values() (url.Values, error) {
	v := url.Values{}

	v.Add("user_id", strconv.Itoa(config.UserID))
	if config.InlineMessageID == "" {
		if config.ChannelUsername == "" {
			v.Add("chat_id", strconv.Itoa(config.ChatID))
		} else {
			v.Add("chat_id", config.ChannelUsername)
		}
		v.Add("message_id", strconv.Itoa(config.MessageID))
	} else {
		v.Add("inline_message_id", config.InlineMessageID)
	}

	return v, nil
}

func (config GetGameHighScoresConfig) method() string {
	return "getGameHighScores"
}

// ChatActionConfig contains information about a SendChatAction request.
type ChatActionConfig struct {
	BaseChat
	Action string // required
}

// values returns a url.Values representation of ChatActionConfig.
func (config ChatActionConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}
	v.Add("action", config.Action)
	return v, nil
}

// method returns Telegram API method name for sending ChatAction.
func (config ChatActionConfig) method() string {
	return "sendChatAction"
}

// EditMessageTextConfig allows you to modify the text in a message.
type EditMessageTextConfig struct {
	BaseEdit
	Text                  string
	ParseMode             string
	DisableWebPagePreview bool
}

func (config EditMessageTextConfig) values() (url.Values, error) {
	v, err := config.BaseEdit.values()
	if err != nil {
		return v, err
	}

	v.Add("text", config.Text)
	v.Add("parse_mode", config.ParseMode)
	v.Add("disable_web_page_preview", strconv.FormatBool(config.DisableWebPagePreview))

	return v, nil
}

func (config EditMessageTextConfig) method() string {
	return "editMessageText"
}

// EditMessageCaptionConfig allows you to modify the caption of a message.
type EditMessageCaptionConfig struct {
	BaseEdit
	Caption   string
	ParseMode string
}

func (config EditMessageCaptionConfig) values() (url.Values, error) {
	v, _ := config.BaseEdit.values()

	v.Add("caption", config.Caption)
	if config.ParseMode != "" {
		v.Add("parse_mode", config.ParseMode)
	}

	return v, nil
}

func (config EditMessageCaptionConfig) method() string {
	return "editMessageCaption"
}

// EditMessageReplyMarkupConfig allows you to modify the reply markup
// of a message.
type EditMessageReplyMarkupConfig struct {
	BaseEdit
}

func (config EditMessageReplyMarkupConfig) values() (url.Values, error) {
	return config.BaseEdit.values()
}

func (config EditMessageReplyMarkupConfig) method() string {
	return "editMessageReplyMarkup"
}

// UserProfilePhotosConfig contains information about a
// GetUserProfilePhotos request.
type UserProfilePhotosConfig struct {
	UserID int
	Offset int
	Limit  int
}

// FileConfig has information about a file hosted on Telegram.
type FileConfig struct {
	FileID string
}

// UpdateConfig contains information about a GetUpdates request.
type UpdateConfig struct {
	Offset  int
	Limit   int
	Timeout int
}

// WebhookConfig contains information about a SetWebhook request.
type WebhookConfig struct {
	URL            *url.URL
	Certificate    interface{}
	MaxConnections int
}

// FileBytes contains information about a set of bytes to upload
// as a File.
type FileBytes struct {
	Name  string
	Bytes []byte
}

// FileReader contains information about a reader to upload as a File.
// If Size is -1, it will read the entire Reader into memory to
// calculate a Size.
type FileReader struct {
	Name   string
	Reader io.Reader
	Size   int64
}

// InlineConfig contains information on making an InlineQuery response.
type InlineConfig struct {
	InlineQueryID     string        `json:"inline_query_id"`
	Results           []interface{} `json:"results"`
	CacheTime         int           `json:"cache_time"`
	IsPersonal        bool          `json:"is_personal"`
	NextOffset        string        `json:"next_offset"`
	SwitchPMText      string        `json:"switch_pm_text"`
	SwitchPMParameter string        `json:"switch_pm_parameter"`
}

// CallbackConfig contains information on making a CallbackQuery response.
type CallbackConfig struct {
	CallbackQueryID string `json:"callback_query_id"`
	Text            string `json:"text"`
	ShowAlert       bool   `json:"show_alert"`
	URL             string `json:"url"`
	CacheTime       int    `json:"cache_time"`
}

// ChatMemberConfig contains information about a user in a chat for use
// with administrative functions such as kicking or unbanning a user.
type ChatMemberConfig struct {
	ChatID             int64
	SuperGroupUsername string
	ChannelUsername    string
	UserID             int
}

// KickChatMemberConfig contains extra fields to kick user
type KickChatMemberConfig struct {
	ChatMemberConfig
	UntilDate int64
}

// RestrictChatMemberConfig contains fields to restrict members of chat
type RestrictChatMemberConfig struct {
	ChatMemberConfig
	UntilDate             int64
	CanSendMessages       *bool
	CanSendMediaMessages  *bool
	CanSendOtherMessages  *bool
	CanAddWebPagePreviews *bool
}

// PromoteChatMemberConfig contains fields to promote members of chat
type PromoteChatMemberConfig struct {
	ChatMemberConfig
	CanChangeInfo      *bool
	CanPostMessages    *bool
	CanEditMessages    *bool
	CanDeleteMessages  *bool
	CanInviteUsers     *bool
	CanRestrictMembers *bool
	CanPinMessages     *bool
	CanPromoteMembers  *bool
}

// ChatConfig contains information about getting information on a chat.
type ChatConfig struct {
	ChatID             int64
	SuperGroupUsername string
}

// ChatConfigWithUser contains information about getting information on
// a specific user within a chat.
type ChatConfigWithUser struct {
	ChatID             int64
	SuperGroupUsername string
	UserID             int
}

// InvoiceConfig contains information for sendInvoice request.
type InvoiceConfig struct {
	BaseChat
	Title               string          // required
	Description         string          // required
	Payload             string          // required
	ProviderToken       string          // required
	StartParameter      string          // required
	Currency            string          // required
	Prices              *[]LabeledPrice // required
	PhotoURL            string
	PhotoSize           int
	PhotoWidth          int
	PhotoHeight         int
	NeedName            bool
	NeedPhoneNumber     bool
	NeedEmail           bool
	NeedShippingAddress bool
	IsFlexible          bool
}

func (config InvoiceConfig) values() (url.Values, error) {
	v, err := config.BaseChat.values()
	if err != nil {
		return v, err
	}
	v.Add("title", config.Title)
	v.Add("description", config.Description)
	v.Add("payload", config.Payload)
	v.Add("provider_token", config.ProviderToken)
	v.Add("start_parameter", config.StartParameter)
	v.Add("currency", config.Currency)
	data, err := json.Marshal(config.Prices)
	if err != nil {
		return v, err
	}
	v.Add("prices", string(data))
	if config.PhotoURL != "" {
		v.Add("photo_url", config.PhotoURL)
	}
	if config.PhotoSize != 0 {
		v.Add("photo_size", strconv.Itoa(config.PhotoSize))
	}
	if config.PhotoWidth != 0 {
		v.Add("photo_width", strconv.Itoa(config.PhotoWidth))
	}
	if config.PhotoHeight != 0 {
		v.Add("photo_height", strconv.Itoa(config.PhotoHeight))
	}
	if config.NeedName != false {
		v.Add("need_name", strconv.FormatBool(config.NeedName))
	}
	if config.NeedPhoneNumber != false {
		v.Add("need_phone_number", strconv.FormatBool(config.NeedPhoneNumber))
	}
	if config.NeedEmail != false {
		v.Add("need_email", strconv.FormatBool(config.NeedEmail))
	}
	if config.NeedShippingAddress != false {
		v.Add("need_shipping_address", strconv.FormatBool(config.NeedShippingAddress))
	}
	if config.IsFlexible != false {
		v.Add("is_flexible", strconv.FormatBool(config.IsFlexible))
	}

	return v, nil
}

func (config InvoiceConfig) method() string {
	return "sendInvoice"
}

// ShippingConfig contains information for answerShippingQuery request.
type ShippingConfig struct {
	ShippingQueryID string // required
	OK              bool   // required
	ShippingOptions *[]ShippingOption
	ErrorMessage    string
}

// PreCheckoutConfig conatins information for answerPreCheckoutQuery request.
type PreCheckoutConfig struct {
	PreCheckoutQueryID string // required
	OK                 bool   // required
	ErrorMessage       string
}

// DeleteMessageConfig contains information of a message in a chat to delete.
type DeleteMessageConfig struct {
	ChatID    int64
	MessageID int
}

func (config DeleteMessageConfig) method() string {
	return "deleteMessage"
}

func (config DeleteMessageConfig) values() (url.Values, error) {
	v := url.Values{}

	v.Add("chat_id", strconv.FormatInt(config.ChatID, 10))
	v.Add("message_id", strconv.Itoa(config.MessageID))

	return v, nil
}

// PinChatMessageConfig contains information of a message in a chat to pin.
type PinChatMessageConfig struct {
	ChatID              int64
	MessageID           int
	DisableNotification bool
}

func (config PinChatMessageConfig) method() string {
	return "pinChatMessage"
}

func (config PinChatMessageConfig) values() (url.Values, error) {
	v := url.Values{}

	v.Add("chat_id", strconv.FormatInt(config.ChatID, 10))
	v.Add("message_id", strconv.Itoa(config.MessageID))
	v.Add("disable_notification", strconv.FormatBool(config.DisableNotification))

	return v, nil
}

// UnpinChatMessageConfig contains information of chat to unpin.
type UnpinChatMessageConfig struct {
	ChatID int64
}

func (config UnpinChatMessageConfig) method() string {
	return "unpinChatMessage"
}

func (config UnpinChatMessageConfig) values() (url.Values, error) {
	v := url.Values{}

	v.Add("chat_id", strconv.FormatInt(config.ChatID, 10))

	return v, nil
}

// SetChatTitleConfig contains information for change chat title.
type SetChatTitleConfig struct {
	ChatID int64
	Title  string
}

func (config SetChatTitleConfig) method() string {
	return "setChatTitle"
}

func (config SetChatTitleConfig) values() (url.Values, error) {
	v := url.Values{}

	v.Add("chat_id", strconv.FormatInt(config.ChatID, 10))
	v.Add("title", config.Title)

	return v, nil
}

// SetChatDescriptionConfig contains information for change chat description.
type SetChatDescriptionConfig struct {
	ChatID      int64
	Description string
}

func (config SetChatDescriptionConfig) method() string {
	return "setChatDescription"
}

func (config SetChatDescriptionConfig) values() (url.Values, error) {
	v := url.Values{}

	v.Add("chat_id", strconv.FormatInt(config.ChatID, 10))
	v.Add("description", config.Description)

	return v, nil
}

// SetChatPhotoConfig contains information for change chat photo
type SetChatPhotoConfig struct {
	BaseFile
}

// name returns the field name for the Photo.
func (config SetChatPhotoConfig) name() string {
	return "photo"
}

// method returns Telegram API method name for sending Photo.
func (config SetChatPhotoConfig) method() string {
	return "setChatPhoto"
}

// DeleteChatPhotoConfig contains information for delete chat photo.
type DeleteChatPhotoConfig struct {
	ChatID int64
}

func (config DeleteChatPhotoConfig) method() string {
	return "deleteChatPhoto"
}

func (config DeleteChatPhotoConfig) values() (url.Values, error) {
	v := url.Values{}

	v.Add("chat_id", strconv.FormatInt(config.ChatID, 10))

	return v, nil
}
