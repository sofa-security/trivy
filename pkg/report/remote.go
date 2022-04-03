package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"net/http"
	"strconv"
	"strings"
)

const serverReceiveURI = "/scanner/vulnerability/result/receive"

// RemoteWriter implements result Writer
type RemoteWriter struct {
	Remote   string // http://host:port
	TaskInfo string //taskId|processNo|taskProcessId
}

type RemoteResult struct {
	TaskId    int64         `json:"task_id"`
	ProcessNo string        `json:"process_no"`
	ProcessId int64         `json:"process_id"`
	Result    types.Results `json:"result"`
}

// Write writes the results in JSON format
func (r RemoteWriter) Write(report types.Report) error {
	result := report.Results
	if result == nil {
		log.Logger.Warn("[RemoteWriter]warning: result remoteWriter got empty result")
		return nil
	}

	infos := strings.Split(r.TaskInfo, "|")
	if len(infos) != 3 {
		log.Logger.Error("[RemoteWriter] invalid taskinfo format, must be taskId|processNo|taskProcessId, your input:" + r.TaskInfo)
		return errors.New("invalid taskinfo format, must be taskId|processNo|taskProcessId, your input:" + r.TaskInfo)
	}

	taskId, _ := strconv.ParseInt(infos[0], 10, 64)
	processId, _ := strconv.ParseInt(infos[2], 10, 64)
	resultData := RemoteResult{
		TaskId:    taskId,
		ProcessNo: infos[1],
		ProcessId: processId,
		Result:    result,
	}
	reqData, err := json.Marshal(resultData)
	if err != nil {
		log.Logger.Error("remote Writer marshal data error :", err)
		return err
	}

	client := http.Client{}
	req, _ := http.NewRequest("POST", strings.TrimRight(r.Remote, "/")+serverReceiveURI, bytes.NewBuffer(reqData))
	resp, err := client.Do(req)
	if err != nil {
		log.Logger.Error("send remote scan result error:", err.Error())
		return err
	}
	defer resp.Body.Close()
	return nil
}
