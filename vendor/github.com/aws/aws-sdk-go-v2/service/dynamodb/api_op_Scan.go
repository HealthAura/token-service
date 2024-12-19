// Code generated by smithy-go-codegen DO NOT EDIT.

package dynamodb

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	internalEndpointDiscovery "github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// The Scan operation returns one or more items and item attributes by accessing
// every item in a table or a secondary index. To have DynamoDB return fewer items,
// you can provide a FilterExpression operation.
//
// If the total size of scanned items exceeds the maximum dataset size limit of 1
// MB, the scan completes and results are returned to the user. The
// LastEvaluatedKey value is also returned and the requestor can use the
// LastEvaluatedKey to continue the scan in a subsequent operation. Each scan
// response also includes number of items that were scanned (ScannedCount) as part
// of the request. If using a FilterExpression , a scan result can result in no
// items meeting the criteria and the Count will result in zero. If you did not
// use a FilterExpression in the scan request, then Count is the same as
// ScannedCount .
//
// Count and ScannedCount only return the count of items specific to a single scan
// request and, unless the table is less than 1MB, do not represent the total
// number of items in the table.
//
// A single Scan operation first reads up to the maximum number of items set (if
// using the Limit parameter) or a maximum of 1 MB of data and then applies any
// filtering to the results if a FilterExpression is provided. If LastEvaluatedKey
// is present in the response, pagination is required to complete the full table
// scan. For more information, see [Paginating the Results]in the Amazon DynamoDB Developer Guide.
//
// Scan operations proceed sequentially; however, for faster performance on a
// large table or secondary index, applications can request a parallel Scan
// operation by providing the Segment and TotalSegments parameters. For more
// information, see [Parallel Scan]in the Amazon DynamoDB Developer Guide.
//
// By default, a Scan uses eventually consistent reads when accessing the items in
// a table. Therefore, the results from an eventually consistent Scan may not
// include the latest item changes at the time the scan iterates through each item
// in the table. If you require a strongly consistent read of each item as the scan
// iterates through the items in the table, you can set the ConsistentRead
// parameter to true. Strong consistency only relates to the consistency of the
// read at the item level.
//
// DynamoDB does not provide snapshot isolation for a scan operation when the
// ConsistentRead parameter is set to true. Thus, a DynamoDB scan operation does
// not guarantee that all reads in a scan see a consistent snapshot of the table
// when the scan operation was requested.
//
// [Paginating the Results]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.Pagination
// [Parallel Scan]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.ParallelScan
func (c *Client) Scan(ctx context.Context, params *ScanInput, optFns ...func(*Options)) (*ScanOutput, error) {
	if params == nil {
		params = &ScanInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "Scan", params, optFns, c.addOperationScanMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ScanOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Represents the input of a Scan operation.
type ScanInput struct {

	// The name of the table containing the requested items or if you provide IndexName
	// , the name of the table to which that index belongs.
	//
	// You can also provide the Amazon Resource Name (ARN) of the table in this
	// parameter.
	//
	// This member is required.
	TableName *string

	// This is a legacy parameter. Use ProjectionExpression instead. For more
	// information, see [AttributesToGet]in the Amazon DynamoDB Developer Guide.
	//
	// [AttributesToGet]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.AttributesToGet.html
	AttributesToGet []string

	// This is a legacy parameter. Use FilterExpression instead. For more information,
	// see [ConditionalOperator]in the Amazon DynamoDB Developer Guide.
	//
	// [ConditionalOperator]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.ConditionalOperator.html
	ConditionalOperator types.ConditionalOperator

	// A Boolean value that determines the read consistency model during the scan:
	//
	//   - If ConsistentRead is false , then the data returned from Scan might not
	//   contain the results from other recently completed write operations ( PutItem ,
	//   UpdateItem , or DeleteItem ).
	//
	//   - If ConsistentRead is true , then all of the write operations that completed
	//   before the Scan began are guaranteed to be contained in the Scan response.
	//
	// The default setting for ConsistentRead is false .
	//
	// The ConsistentRead parameter is not supported on global secondary indexes. If
	// you scan a global secondary index with ConsistentRead set to true, you will
	// receive a ValidationException .
	ConsistentRead *bool

	// The primary key of the first item that this operation will evaluate. Use the
	// value that was returned for LastEvaluatedKey in the previous operation.
	//
	// The data type for ExclusiveStartKey must be String, Number or Binary. No set
	// data types are allowed.
	//
	// In a parallel scan, a Scan request that includes ExclusiveStartKey must specify
	// the same segment whose previous Scan returned the corresponding value of
	// LastEvaluatedKey .
	ExclusiveStartKey map[string]types.AttributeValue

	// One or more substitution tokens for attribute names in an expression. The
	// following are some use cases for using ExpressionAttributeNames :
	//
	//   - To access an attribute whose name conflicts with a DynamoDB reserved word.
	//
	//   - To create a placeholder for repeating occurrences of an attribute name in
	//   an expression.
	//
	//   - To prevent special characters in an attribute name from being
	//   misinterpreted in an expression.
	//
	// Use the # character in an expression to dereference an attribute name. For
	// example, consider the following attribute name:
	//
	//   - Percentile
	//
	// The name of this attribute conflicts with a reserved word, so it cannot be used
	// directly in an expression. (For the complete list of reserved words, see [Reserved Words]in the
	// Amazon DynamoDB Developer Guide). To work around this, you could specify the
	// following for ExpressionAttributeNames :
	//
	//   - {"#P":"Percentile"}
	//
	// You could then use this substitution in an expression, as in this example:
	//
	//   - #P = :val
	//
	// Tokens that begin with the : character are expression attribute values, which
	// are placeholders for the actual value at runtime.
	//
	// For more information on expression attribute names, see [Specifying Item Attributes] in the Amazon DynamoDB
	// Developer Guide.
	//
	// [Reserved Words]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ReservedWords.html
	// [Specifying Item Attributes]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.AccessingItemAttributes.html
	ExpressionAttributeNames map[string]string

	// One or more values that can be substituted in an expression.
	//
	// Use the : (colon) character in an expression to dereference an attribute value.
	// For example, suppose that you wanted to check whether the value of the
	// ProductStatus attribute was one of the following:
	//
	//     Available | Backordered | Discontinued
	//
	// You would first need to specify ExpressionAttributeValues as follows:
	//
	//     { ":avail":{"S":"Available"}, ":back":{"S":"Backordered"},
	//     ":disc":{"S":"Discontinued"} }
	//
	// You could then use these values in an expression, such as this:
	//
	//     ProductStatus IN (:avail, :back, :disc)
	//
	// For more information on expression attribute values, see [Condition Expressions] in the Amazon
	// DynamoDB Developer Guide.
	//
	// [Condition Expressions]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.SpecifyingConditions.html
	ExpressionAttributeValues map[string]types.AttributeValue

	// A string that contains conditions that DynamoDB applies after the Scan
	// operation, but before the data is returned to you. Items that do not satisfy the
	// FilterExpression criteria are not returned.
	//
	// A FilterExpression is applied after the items have already been read; the
	// process of filtering does not consume any additional read capacity units.
	//
	// For more information, see [Filter Expressions] in the Amazon DynamoDB Developer Guide.
	//
	// [Filter Expressions]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.FilterExpression
	FilterExpression *string

	// The name of a secondary index to scan. This index can be any local secondary
	// index or global secondary index. Note that if you use the IndexName parameter,
	// you must also provide TableName .
	IndexName *string

	// The maximum number of items to evaluate (not necessarily the number of matching
	// items). If DynamoDB processes the number of items up to the limit while
	// processing the results, it stops the operation and returns the matching values
	// up to that point, and a key in LastEvaluatedKey to apply in a subsequent
	// operation, so that you can pick up where you left off. Also, if the processed
	// dataset size exceeds 1 MB before DynamoDB reaches this limit, it stops the
	// operation and returns the matching values up to the limit, and a key in
	// LastEvaluatedKey to apply in a subsequent operation to continue the operation.
	// For more information, see [Working with Queries]in the Amazon DynamoDB Developer Guide.
	//
	// [Working with Queries]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/QueryAndScan.html
	Limit *int32

	// A string that identifies one or more attributes to retrieve from the specified
	// table or index. These attributes can include scalars, sets, or elements of a
	// JSON document. The attributes in the expression must be separated by commas.
	//
	// If no attribute names are specified, then all attributes will be returned. If
	// any of the requested attributes are not found, they will not appear in the
	// result.
	//
	// For more information, see [Specifying Item Attributes] in the Amazon DynamoDB Developer Guide.
	//
	// [Specifying Item Attributes]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.AccessingItemAttributes.html
	ProjectionExpression *string

	// Determines the level of detail about either provisioned or on-demand throughput
	// consumption that is returned in the response:
	//
	//   - INDEXES - The response includes the aggregate ConsumedCapacity for the
	//   operation, together with ConsumedCapacity for each table and secondary index
	//   that was accessed.
	//
	// Note that some operations, such as GetItem and BatchGetItem , do not access any
	//   indexes at all. In these cases, specifying INDEXES will only return
	//   ConsumedCapacity information for table(s).
	//
	//   - TOTAL - The response includes only the aggregate ConsumedCapacity for the
	//   operation.
	//
	//   - NONE - No ConsumedCapacity details are included in the response.
	ReturnConsumedCapacity types.ReturnConsumedCapacity

	// This is a legacy parameter. Use FilterExpression instead. For more information,
	// see [ScanFilter]in the Amazon DynamoDB Developer Guide.
	//
	// [ScanFilter]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.ScanFilter.html
	ScanFilter map[string]types.Condition

	// For a parallel Scan request, Segment identifies an individual segment to be
	// scanned by an application worker.
	//
	// Segment IDs are zero-based, so the first segment is always 0. For example, if
	// you want to use four application threads to scan a table or an index, then the
	// first thread specifies a Segment value of 0, the second thread specifies 1, and
	// so on.
	//
	// The value of LastEvaluatedKey returned from a parallel Scan request must be
	// used as ExclusiveStartKey with the same segment ID in a subsequent Scan
	// operation.
	//
	// The value for Segment must be greater than or equal to 0, and less than the
	// value provided for TotalSegments .
	//
	// If you provide Segment , you must also provide TotalSegments .
	Segment *int32

	// The attributes to be returned in the result. You can retrieve all item
	// attributes, specific item attributes, the count of matching items, or in the
	// case of an index, some or all of the attributes projected into the index.
	//
	//   - ALL_ATTRIBUTES - Returns all of the item attributes from the specified table
	//   or index. If you query a local secondary index, then for each matching item in
	//   the index, DynamoDB fetches the entire item from the parent table. If the index
	//   is configured to project all item attributes, then all of the data can be
	//   obtained from the local secondary index, and no fetching is required.
	//
	//   - ALL_PROJECTED_ATTRIBUTES - Allowed only when querying an index. Retrieves
	//   all attributes that have been projected into the index. If the index is
	//   configured to project all attributes, this return value is equivalent to
	//   specifying ALL_ATTRIBUTES .
	//
	//   - COUNT - Returns the number of matching items, rather than the matching items
	//   themselves. Note that this uses the same quantity of read capacity units as
	//   getting the items, and is subject to the same item size calculations.
	//
	//   - SPECIFIC_ATTRIBUTES - Returns only the attributes listed in
	//   ProjectionExpression . This return value is equivalent to specifying
	//   ProjectionExpression without specifying any value for Select .
	//
	// If you query or scan a local secondary index and request only attributes that
	//   are projected into that index, the operation reads only the index and not the
	//   table. If any of the requested attributes are not projected into the local
	//   secondary index, DynamoDB fetches each of these attributes from the parent
	//   table. This extra fetching incurs additional throughput cost and latency.
	//
	// If you query or scan a global secondary index, you can only request attributes
	//   that are projected into the index. Global secondary index queries cannot fetch
	//   attributes from the parent table.
	//
	// If neither Select nor ProjectionExpression are specified, DynamoDB defaults to
	// ALL_ATTRIBUTES when accessing a table, and ALL_PROJECTED_ATTRIBUTES when
	// accessing an index. You cannot use both Select and ProjectionExpression
	// together in a single request, unless the value for Select is SPECIFIC_ATTRIBUTES
	// . (This usage is equivalent to specifying ProjectionExpression without any
	// value for Select .)
	//
	// If you use the ProjectionExpression parameter, then the value for Select can
	// only be SPECIFIC_ATTRIBUTES . Any other value for Select will return an error.
	Select types.Select

	// For a parallel Scan request, TotalSegments represents the total number of
	// segments into which the Scan operation will be divided. The value of
	// TotalSegments corresponds to the number of application workers that will perform
	// the parallel scan. For example, if you want to use four application threads to
	// scan a table or an index, specify a TotalSegments value of 4.
	//
	// The value for TotalSegments must be greater than or equal to 1, and less than
	// or equal to 1000000. If you specify a TotalSegments value of 1, the Scan
	// operation will be sequential rather than parallel.
	//
	// If you specify TotalSegments , you must also specify Segment .
	TotalSegments *int32

	noSmithyDocumentSerde
}

// Represents the output of a Scan operation.
type ScanOutput struct {

	// The capacity units consumed by the Scan operation. The data returned includes
	// the total provisioned throughput consumed, along with statistics for the table
	// and any indexes involved in the operation. ConsumedCapacity is only returned if
	// the ReturnConsumedCapacity parameter was specified. For more information, see [Capacity unit consumption for read operations]
	// in the Amazon DynamoDB Developer Guide.
	//
	// [Capacity unit consumption for read operations]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#read-operation-consumption
	ConsumedCapacity *types.ConsumedCapacity

	// The number of items in the response.
	//
	// If you set ScanFilter in the request, then Count is the number of items
	// returned after the filter was applied, and ScannedCount is the number of
	// matching items before the filter was applied.
	//
	// If you did not use a filter in the request, then Count is the same as
	// ScannedCount .
	Count int32

	// An array of item attributes that match the scan criteria. Each element in this
	// array consists of an attribute name and the value for that attribute.
	Items []map[string]types.AttributeValue

	// The primary key of the item where the operation stopped, inclusive of the
	// previous result set. Use this value to start a new operation, excluding this
	// value in the new request.
	//
	// If LastEvaluatedKey is empty, then the "last page" of results has been
	// processed and there is no more data to be retrieved.
	//
	// If LastEvaluatedKey is not empty, it does not necessarily mean that there is
	// more data in the result set. The only way to know when you have reached the end
	// of the result set is when LastEvaluatedKey is empty.
	LastEvaluatedKey map[string]types.AttributeValue

	// The number of items evaluated, before any ScanFilter is applied. A high
	// ScannedCount value with few, or no, Count results indicates an inefficient Scan
	// operation. For more information, see [Count and ScannedCount]in the Amazon DynamoDB Developer Guide.
	//
	// If you did not use a filter in the request, then ScannedCount is the same as
	// Count .
	//
	// [Count and ScannedCount]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/QueryAndScan.html#Count
	ScannedCount int32

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationScanMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsjson10_serializeOpScan{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson10_deserializeOpScan{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "Scan"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addSpanRetryLoop(stack, options); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpScanDiscoverEndpointMiddleware(stack, options, c); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = addUserAgentRetryMode(stack, options); err != nil {
		return err
	}
	if err = addOpScanValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opScan(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addValidateResponseChecksum(stack, options); err != nil {
		return err
	}
	if err = addAcceptEncodingGzip(stack, options); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	if err = addSpanInitializeStart(stack); err != nil {
		return err
	}
	if err = addSpanInitializeEnd(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestStart(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestEnd(stack); err != nil {
		return err
	}
	return nil
}

// ScanPaginatorOptions is the paginator options for Scan
type ScanPaginatorOptions struct {
	// The maximum number of items to evaluate (not necessarily the number of matching
	// items). If DynamoDB processes the number of items up to the limit while
	// processing the results, it stops the operation and returns the matching values
	// up to that point, and a key in LastEvaluatedKey to apply in a subsequent
	// operation, so that you can pick up where you left off. Also, if the processed
	// dataset size exceeds 1 MB before DynamoDB reaches this limit, it stops the
	// operation and returns the matching values up to the limit, and a key in
	// LastEvaluatedKey to apply in a subsequent operation to continue the operation.
	// For more information, see [Working with Queries]in the Amazon DynamoDB Developer Guide.
	//
	// [Working with Queries]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/QueryAndScan.html
	Limit int32
}

// ScanPaginator is a paginator for Scan
type ScanPaginator struct {
	options   ScanPaginatorOptions
	client    ScanAPIClient
	params    *ScanInput
	nextToken map[string]types.AttributeValue
	firstPage bool
}

// NewScanPaginator returns a new ScanPaginator
func NewScanPaginator(client ScanAPIClient, params *ScanInput, optFns ...func(*ScanPaginatorOptions)) *ScanPaginator {
	if params == nil {
		params = &ScanInput{}
	}

	options := ScanPaginatorOptions{}
	if params.Limit != nil {
		options.Limit = *params.Limit
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &ScanPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.ExclusiveStartKey,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *ScanPaginator) HasMorePages() bool {
	return p.firstPage || p.nextToken != nil
}

// NextPage retrieves the next Scan page.
func (p *ScanPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*ScanOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.ExclusiveStartKey = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.Limit = limit

	optFns = append([]func(*Options){
		addIsPaginatorUserAgent,
	}, optFns...)
	result, err := p.client.Scan(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.LastEvaluatedKey

	_ = prevToken

	return result, nil
}

func addOpScanDiscoverEndpointMiddleware(stack *middleware.Stack, o Options, c *Client) error {
	return stack.Finalize.Insert(&internalEndpointDiscovery.DiscoverEndpoint{
		Options: []func(*internalEndpointDiscovery.DiscoverEndpointOptions){
			func(opt *internalEndpointDiscovery.DiscoverEndpointOptions) {
				opt.DisableHTTPS = o.EndpointOptions.DisableHTTPS
				opt.Logger = o.Logger
			},
		},
		DiscoverOperation:            c.fetchOpScanDiscoverEndpoint,
		EndpointDiscoveryEnableState: o.EndpointDiscovery.EnableEndpointDiscovery,
		EndpointDiscoveryRequired:    false,
		Region:                       o.Region,
	}, "ResolveEndpointV2", middleware.After)
}

func (c *Client) fetchOpScanDiscoverEndpoint(ctx context.Context, region string, optFns ...func(*internalEndpointDiscovery.DiscoverEndpointOptions)) (internalEndpointDiscovery.WeightedAddress, error) {
	input := getOperationInput(ctx)
	in, ok := input.(*ScanInput)
	if !ok {
		return internalEndpointDiscovery.WeightedAddress{}, fmt.Errorf("unknown input type %T", input)
	}
	_ = in

	identifierMap := make(map[string]string, 0)
	identifierMap["sdk#Region"] = region

	key := fmt.Sprintf("DynamoDB.%v", identifierMap)

	if v, ok := c.endpointCache.Get(key); ok {
		return v, nil
	}

	discoveryOperationInput := &DescribeEndpointsInput{}

	opt := internalEndpointDiscovery.DiscoverEndpointOptions{}
	for _, fn := range optFns {
		fn(&opt)
	}

	go c.handleEndpointDiscoveryFromService(ctx, discoveryOperationInput, region, key, opt)
	return internalEndpointDiscovery.WeightedAddress{}, nil
}

// ScanAPIClient is a client that implements the Scan operation.
type ScanAPIClient interface {
	Scan(context.Context, *ScanInput, ...func(*Options)) (*ScanOutput, error)
}

var _ ScanAPIClient = (*Client)(nil)

func newServiceMetadataMiddleware_opScan(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "Scan",
	}
}
